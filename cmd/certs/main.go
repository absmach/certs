// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/absmach/certs"
	"github.com/absmach/certs/api"
	certsgrpc "github.com/absmach/certs/api/grpc"
	httpapi "github.com/absmach/certs/api/http"
	jaegerClient "github.com/absmach/certs/internal/jaeger"
	"github.com/absmach/certs/internal/prometheus"
	"github.com/absmach/certs/internal/server"
	grpcserver "github.com/absmach/certs/internal/server/grpc"
	"github.com/absmach/certs/internal/uuid"
	"github.com/absmach/certs/pki"
	"github.com/absmach/certs/tracing"
	smq "github.com/absmach/supermq/pkg/server"
	httpserver "github.com/absmach/supermq/pkg/server/http"
	"github.com/caarlos0/env/v10"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName        = "certs"
	envPrefixHTTP  = "AM_CERTS_HTTP_"
	envPrefixGRPC  = "AM_CERTS_GRPC_"
	envPrefixAuth  = "AM_AUTH_GRPC_"
	defSvcHTTPPort = "9010"
	defSvcGRPCPort = "7012"
)

type config struct {
	LogLevel   string  `env:"AM_COMPUTATIONS_LOG_LEVEL"     envDefault:"info"`
	JaegerURL  url.URL `env:"AM_JAEGER_URL"                 envDefault:"http://jaeger:4318"`
	InstanceID string  `env:"AM_COMPUTATIONS_INSTANCE_ID"   envDefault:""`
	TraceRatio float64 `env:"AM_JAEGER_TRACE_RATIO"         envDefault:"1.0"`

	// OpenBao PKI settings
	OpenBaoHost      string `env:"AM_CERTS_OPENBAO_HOST"         envDefault:"http://localhost:8200"`
	OpenBaoAppRole   string `env:"AM_CERTS_OPENBAO_APP_ROLE"     envDefault:""`
	OpenBaoAppSecret string `env:"AM_CERTS_OPENBAO_APP_SECRET"   envDefault:""`
	OpenBaoNamespace string `env:"AM_CERTS_OPENBAO_NAMESPACE"    envDefault:""`
	OpenBaoPKIPath   string `env:"AM_CERTS_OPENBAO_PKI_PATH"     envDefault:"pki"`
	OpenBaoRole      string `env:"AM_CERTS_OPENBAO_ROLE"         envDefault:"certs"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := initLogger(cfg.LogLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if cfg.InstanceID == "" {
		cfg.InstanceID, err = uuid.New().ID()
		if err != nil {
			log.Fatalf(fmt.Sprintf("failed to generate instance ID: %s", err))
		}
	}

	if cfg.OpenBaoHost == "" {
		logger.Error("No host specified for OpenBao PKI engine")
		return
	}

	if cfg.OpenBaoAppRole == "" || cfg.OpenBaoAppSecret == "" {
		logger.Error("OpenBao AppRole credentials not specified")
		return
	}

	pkiAgent, err := pki.NewAgent(cfg.OpenBaoAppRole, cfg.OpenBaoAppSecret, cfg.OpenBaoHost, cfg.OpenBaoNamespace, cfg.OpenBaoPKIPath, cfg.OpenBaoRole, logger)
	if err != nil {
		logger.Error("failed to configure client for OpenBao PKI engine")
		return
	}

	tp, err := jaegerClient.NewProvider(ctx, svcName, cfg.JaegerURL, cfg.InstanceID, cfg.TraceRatio)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to init Jaeger: %s", err))
	}
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			logger.Error(fmt.Sprintf("Error shutting down tracer provider: %v", err))
		}
	}()
	tracer := tp.Tracer(svcName)

	httpServerConfig := smq.Config{Port: defSvcHTTPPort}
	if err := env.ParseWithOptions(&httpServerConfig, env.Options{Prefix: envPrefixHTTP}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC server configuration : %s", svcName, err))
	}

	svc := newService(ctx, tracer, logger, pkiAgent)

	grpcServerConfig := smq.Config{Port: defSvcGRPCPort}
	if err := env.ParseWithOptions(&grpcServerConfig, env.Options{Prefix: envPrefixGRPC}); err != nil {
		log.Printf("failed to load %s gRPC server configuration : %s", svcName, err.Error())
		return
	}

	registerCertsServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		certs.RegisterCertsServiceServer(srv, certsgrpc.NewServer(svc))
	}
	gs := grpcserver.NewServer(ctx, cancel, svcName, grpcServerConfig, registerCertsServiceServer, logger, nil, nil)

	hs := httpserver.NewServer(ctx, cancel, svcName, httpServerConfig, httpapi.MakeHandler(svc, logger, cfg.InstanceID), logger)

	g.Go(func() error {
		return hs.Start()
	})

	g.Go(func() error {
		return gs.Start()
	})

	g.Go(func() error {
		return server.StopSignalHandler(ctx, cancel, logger, svcName, hs, gs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s service terminated: %s", svcName, err))
	}
}

func newService(ctx context.Context, tracer trace.Tracer, logger *slog.Logger, pkiAgent certs.Agent) certs.Service {
	svc, err := certs.NewService(ctx, pkiAgent)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create service: %s", err))
		return nil
	}
	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := prometheus.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)
	svc = tracing.New(svc, tracer)

	return svc
}

func initLogger(levelText string) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(levelText)); err != nil {
		return &slog.Logger{}, fmt.Errorf(`{"level":"error","message":"%s: %s","ts":"%s"}`, err, levelText, time.RFC3339Nano)
	}

	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(logHandler), nil
}
