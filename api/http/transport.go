// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/absmach/certs"
	"github.com/absmach/certs/errors"
	"github.com/go-chi/chi/v5"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/crypto/ocsp"
)

var idPKIXOCSPBasic = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 7, 48, 1, 1})

const (
	offsetKey       = "offset"
	limitKey        = "limit"
	entityKey       = "entity_id"
	commonName      = "common_name"
	approve         = "approve"
	status          = "status"
	token           = "token"
	ocspStatusParam = "force_status"
	entityIDParam   = "entityID"
	ttl             = "ttl"
	defOffset       = 0
	defLimit        = 10
	defType         = 1
)

type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc certs.Service, logger *slog.Logger, instanceID string) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(loggingErrorEncoder(logger, EncodeError)),
	}

	r := chi.NewRouter()

	r.Route("/certs", func(r chi.Router) {
		r.Post("/issue/{entityID}", otelhttp.NewHandler(kithttp.NewServer(
			issueCertEndpoint(svc),
			decodeIssueCert,
			EncodeResponse,
			opts...,
		), "issue_cert").ServeHTTP)
		r.Patch("/{id}/renew", otelhttp.NewHandler(kithttp.NewServer(
			renewCertEndpoint(svc),
			decodeView,
			EncodeResponse,
			opts...,
		), "renew_cert").ServeHTTP)
		r.Patch("/{id}/revoke", otelhttp.NewHandler(kithttp.NewServer(
			revokeCertEndpoint(svc),
			decodeView,
			EncodeResponse,
			opts...,
		), "revoke_cert").ServeHTTP)
		r.Delete("/{entityID}/delete", otelhttp.NewHandler(kithttp.NewServer(
			deleteCertEndpoint(svc),
			decodeDelete,
			EncodeResponse,
			opts...,
		), "delete_cert").ServeHTTP)
		r.Get("/{id}/download/token", otelhttp.NewHandler(kithttp.NewServer(
			requestCertDownloadTokenEndpoint(svc),
			decodeView,
			EncodeResponse,
			opts...,
		), "get_download_token").ServeHTTP)
		r.Get("/", otelhttp.NewHandler(kithttp.NewServer(
			listCertsEndpoint(svc),
			decodeListCerts,
			EncodeResponse,
			opts...,
		), "list_certs").ServeHTTP)
		r.Get("/{id}", otelhttp.NewHandler(kithttp.NewServer(
			viewCertEndpoint(svc),
			decodeView,
			EncodeResponse,
			opts...,
		), "view_cert").ServeHTTP)
		r.Get("/{id}/download", otelhttp.NewHandler(kithttp.NewServer(
			downloadCertEndpoint(svc),
			decodeDownloadCerts,
			encodeFileDownloadResponse,
			opts...,
		), "download_cert").ServeHTTP)
		r.Post("/ocsp", otelhttp.NewHandler(kithttp.NewServer(
			ocspEndpoint(svc),
			decodeOCSPRequest,
			encodeOSCPResponse,
			opts...,
		), "ocsp").ServeHTTP)
		r.Get("/crl", otelhttp.NewHandler(kithttp.NewServer(
			generateCRLEndpoint(svc),
			decodeCRL,
			EncodeResponse,
			opts...,
		), "generate_crl").ServeHTTP)
		r.Get("/get-ca/token", otelhttp.NewHandler(kithttp.NewServer(
			getDownloadCATokenEndpoint(svc),
			decodeView,
			EncodeResponse,
			opts...,
		), "get_ca_token").ServeHTTP)
		r.Get("/view-ca", otelhttp.NewHandler(kithttp.NewServer(
			viewCAEndpoint(svc),
			decodeDownloadCA,
			EncodeResponse,
			opts...,
		), "view_ca").ServeHTTP)
		r.Get("/download-ca", otelhttp.NewHandler(kithttp.NewServer(
			downloadCAEndpoint(svc),
			decodeDownloadCA,
			encodeCADownloadResponse,
			opts...,
		), "download_ca").ServeHTTP)
		r.Route("/csrs", func(r chi.Router) {
			r.Post("/{entityID}", otelhttp.NewHandler(kithttp.NewServer(
				issueFromCSREndpoint(svc),
				decodeIssueFromCSR,
				EncodeResponse,
				opts...,
			), "issue_from_csr").ServeHTTP)
		})
	})

	r.Get("/health", certs.Health("certs", instanceID))
	r.Handle("/metrics", promhttp.Handler())

	return r
}

func decodeView(_ context.Context, r *http.Request) (interface{}, error) {
	req := viewReq{
		id: chi.URLParam(r, "id"),
	}
	return req, nil
}

func decodeDelete(_ context.Context, r *http.Request) (interface{}, error) {
	req := deleteReq{
		entityID: chi.URLParam(r, "entityID"),
	}
	return req, nil
}

func decodeCRL(_ context.Context, r *http.Request) (interface{}, error) {
	certType, err := readNumQuery(r, "", defType)
	if err != nil {
		return nil, err
	}
	req := crlReq{
		certtype: certs.CertType(certType),
	}
	return req, nil
}

func decodeDownloadCerts(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := readStringQuery(r, token, "")
	if err != nil {
		return nil, err
	}
	req := downloadReq{
		token: token,
		id:    chi.URLParam(r, "id"),
	}

	return req, nil
}

func decodeDownloadCA(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := readStringQuery(r, token, "")
	if err != nil {
		return nil, err
	}
	req := downloadReq{
		token: token,
	}

	return req, nil
}

func decodeOCSPRequest(_ context.Context, r *http.Request) (interface{}, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	req, err := ocsp.ParseRequest(body)
	if err != nil {
		return nil, err
	}
	request := ocspReq{
		req:         req,
		statusParam: strings.TrimSpace(r.URL.Query().Get(ocspStatusParam)),
	}
	return request, nil
}

func decodeIssueCert(_ context.Context, r *http.Request) (interface{}, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	cn, err := readStringQuery(r, commonName, "")
	if err != nil {
		return nil, err
	}
	if cn == "" {
		return nil, ErrMissingCN
	}
	req := issueCertReq{
		entityID: chi.URLParam(r, entityIDParam),
		Options: certs.SubjectOptions{
			CommonName: cn,
		},
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errors.Wrap(ErrInvalidRequest, err)
	}
	return req, nil
}

func decodeListCerts(_ context.Context, r *http.Request) (interface{}, error) {
	o, err := readNumQuery(r, offsetKey, defOffset)
	if err != nil {
		return nil, err
	}

	l, err := readNumQuery(r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	entity, err := readStringQuery(r, entityKey, "")
	if err != nil {
		return nil, err
	}

	req := listCertsReq{
		pm: certs.PageMetadata{
			Offset:   o,
			Limit:    l,
			EntityID: entity,
		},
	}
	return req, nil
}

func decodeIssueFromCSR(_ context.Context, r *http.Request) (interface{}, error) {
	t, err := readStringQuery(r, ttl, "")
	if err != nil {
		return nil, err
	}

	req := IssueFromCSRReq{
		entityID: chi.URLParam(r, "entityID"),
		ttl:      t,
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidRequest, errors.New("failed to read request body"))
	}
	defer r.Body.Close()

	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errors.Wrap(ErrInvalidRequest, errors.New("failed to decode JSON"))
	}

	return req, nil
}

// EncodeResponse encodes successful response.
func EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	if ar, ok := response.(Response); ok {
		for k, v := range ar.Headers() {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(ar.Code())

		if ar.Empty() {
			return nil
		}
	}

	return json.NewEncoder(w).Encode(response)
}

func encodeOSCPResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	res := response.(ocspRes)
	if res.template.Certificate == nil {
		ocspRes, err := asn1.Marshal(responseASN1{
			Status: asn1.Enumerated(ocsp.Malformed),
			Response: responseBytes{
				ResponseType: idPKIXOCSPBasic,
			},
		})
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", OCSPType)
		if _, err := w.Write(ocspRes); err != nil {
			return err
		}

		return err
	}

	ocspRes, err := ocsp.CreateResponse(res.issuerCert, res.template.Certificate, res.template, res.signer)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", OCSPType)
	if _, err := w.Write(ocspRes); err != nil {
		return err
	}
	return err
}

func encodeFileDownloadResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(fileDownloadRes)
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)

	f, err := zw.Create("ca.pem")
	if err != nil {
		return err
	}

	if _, err = f.Write(resp.CA); err != nil {
		return err
	}

	f, err = zw.Create("cert.pem")
	if err != nil {
		return err
	}

	if _, err = f.Write(resp.Certificate); err != nil {
		return err
	}

	f, err = zw.Create("key.pem")
	if err != nil {
		return err
	}

	if _, err = f.Write(resp.PrivateKey); err != nil {
		return err
	}

	if err := zw.Close(); err != nil {
		return err
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", resp.Filename))
	w.Header().Set("Content-Type", resp.ContentType)

	_, err = w.Write(buffer.Bytes())

	return err
}

func encodeCADownloadResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(fileDownloadRes)
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)

	f, err := zw.Create("ca.crt")
	if err != nil {
		return err
	}

	if _, err = f.Write(resp.Certificate); err != nil {
		return err
	}

	if len(resp.PrivateKey) > 0 {
		f, err = zw.Create("ca.key")
		if err != nil {
			return err
		}

		if _, err = f.Write(resp.PrivateKey); err != nil {
			return err
		}
	}

	if err := zw.Close(); err != nil {
		return err
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", resp.Filename))
	w.Header().Set("Content-Type", resp.ContentType)

	_, err = w.Write(buffer.Bytes())

	return err
}

// loggingErrorEncoder is a go-kit error encoder logging decorator.
func loggingErrorEncoder(logger *slog.Logger, enc kithttp.ErrorEncoder) kithttp.ErrorEncoder {
	return func(ctx context.Context, err error, w http.ResponseWriter) {
		if errors.Contains(err, ErrValidation) {
			logger.Error(err.Error())
		}
		enc(ctx, err, w)
	}
}

// readStringQuery reads the value of string http query parameters for a given key.
func readStringQuery(r *http.Request, key, def string) (string, error) {
	vals := r.URL.Query()[key]
	if len(vals) > 1 {
		return "", ErrInvalidQueryParams
	}

	if len(vals) == 0 {
		return def, nil
	}

	return vals[0], nil
}

// readNumQuery returns a numeric value.
func readNumQuery(r *http.Request, key string, def uint64) (uint64, error) {
	vals := r.URL.Query()[key]
	if len(vals) > 1 {
		return 0, ErrInvalidQueryParams
	}
	if len(vals) == 0 {
		return def, nil
	}
	val := vals[0]

	v, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return 0, errors.Wrap(ErrInvalidQueryParams, err)
	}
	return v, nil
}
