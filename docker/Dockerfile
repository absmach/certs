FROM golang:1.22-alpine AS builder

ARG SVC
ARG GOARCH
ARG GOARM
ARG VERSION
ARG COMMIT
ARG TIME

WORKDIR /app

COPY . .

RUN apk update \
    && apk add make \
    && make $SVC \
    && mv build/$SVC /exe

FROM scratch

# Required for billing service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /exe /
ENTRYPOINT ["/exe"]
