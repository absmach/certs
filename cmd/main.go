// Copyright (c) Ultraviolet
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/absmach/certs"
	"github.com/absmach/certs/api"
	certsgrpc "github.com/absmach/certs/api/grpc"
	httpapi "github.com/absmach/certs/api/http"
	cpostgres "github.com/absmach/certs/postgres"
	"github.com/absmach/certs/tracing"
	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/pkg/auth"
	jaegerClient "github.com/absmach/magistrala/pkg/clients/jaeger"
	pgClient "github.com/absmach/magistrala/pkg/clients/postgres"
	"github.com/absmach/magistrala/pkg/postgres"
	"github.com/absmach/magistrala/pkg/server"
	grpcserver "github.com/absmach/magistrala/pkg/server/grpc"
	httpserver "github.com/absmach/magistrala/pkg/server/http"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/caarlos0/env/v10"
	"github.com/go-chi/chi"
	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName        = "certs"
	envPrefix      = "AM_CERTS_"
	envPrefixHTTP  = "AM_CERTS_HTTP_"
	envPrefixGRPC  = "AM_CERTS_GRPC_"
	envPrefixAuth  = "AM_AUTH_GRPC_"
	defDB          = "certs"
	defSvcHTTPPort = "9010"
	defSvcGRPCPort = "7012"
)

type config struct {
	LogLevel   string `env:"AM_COMPUTATIONS_LOG_LEVEL"     envDefault:"info"`
	JaegerURL  string `env:"AM_JAEGER_URL"                 envDefault:"http://jaeger:4318"`
	InstanceID string `env:"AM_COMPUTATIONS_INSTANCE_ID"   envDefault:""`
	CAKey      string `env:"AM_CERTS_CA_KEY" envDefault:""`
	CACert     string `env:"AM_CERTS_CA_CERT" envDefault:""`
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

	db, err := pgClient.Setup(envPrefix, *cpostgres.Migration())
	if err != nil {
		log.Fatalf(fmt.Sprintf("Failed to connect to %s database: %s", svcName, err))
	}
	defer db.Close()

	tp, err := jaegerClient.NewProvider(ctx, svcName, cfg.JaegerURL, cfg.InstanceID)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to init Jaeger: %s", err))
	}
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			logger.Error(fmt.Sprintf("Error shutting down tracer provider: %v", err))
		}
	}()
	tracer := tp.Tracer(svcName)

	authConfig := auth.Config{}
	if err := env.ParseWithOptions(&authConfig, env.Options{Prefix: envPrefixAuth}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
	}

	authClient, authHandler, err := auth.Setup(authConfig)
	if err != nil {
		logger.Error(err.Error())
	}
	defer authHandler.Close()

	httpServerConfig := server.Config{Port: defSvcHTTPPort}
	if err := env.ParseWithOptions(&httpServerConfig, env.Options{Prefix: envPrefixHTTP}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC server configuration : %s", svcName, err))
	}

	logger.Info("Successfully connected to users grpc server " + authHandler.Secure())
	svc, err := newService(ctx, db, authClient, tracer, logger, cfg.CACert, cfg.CAKey)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create %s service: %s", svcName, err))
		return
	}

	grpcServerConfig := server.Config{Port: defSvcGRPCPort}
	if err := env.ParseWithOptions(&grpcServerConfig, env.Options{Prefix: envPrefixGRPC}); err != nil {
		log.Printf("failed to load %s gRPC server configuration : %s", svcName, err.Error())
		return
	}

	registerCertsServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		certs.RegisterCertsServiceServer(srv, certsgrpc.NewServer(svc))
	}
	gs := grpcserver.New(ctx, cancel, svcName, grpcServerConfig, registerCertsServiceServer, logger, nil, nil)

	hs := httpserver.New(ctx, cancel, svcName, httpServerConfig, httpapi.MakeHandler(chi.NewMux(), svc, logger, cfg.InstanceID), logger)

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

func newService(ctx context.Context, db *sqlx.DB, authClient magistrala.AuthServiceClient, tracer trace.Tracer, logger *slog.Logger, rootCA, rootCAKey string) (certs.Service, error) {
	database := postgres.NewDatabase(db, tracer)
	repo := cpostgres.NewRepository(database)
	idp := uuid.New()
	svc, err := certs.NewService(ctx, repo, authClient, idp, logger, rootCA, rootCAKey)
	if err != nil {
		return nil, err
	}
	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := internal.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)
	svc = tracing.New(svc, tracer)

	return svc, nil
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
