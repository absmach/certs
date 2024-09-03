FROM golang:1.23-alpine AS builder

ARG SVC

WORKDIR /go/src/github.com/absmach/certs

COPY . .

RUN apk update \
    && apk add make upx\
    && make $SVC \
    && upx build/$SVC \
    && mv build/$SVC /exe

FROM scratch

# Required for billing service
COPY --from=builder /exe /
ENTRYPOINT ["/exe"]
