FROM golang:1.11.1 AS builder

WORKDIR /go/src/github.com/securityscorecard/vault-vouch
ADD . .

ENV CGO_ENABLED=0

RUN go get -v github.com/Masterminds/glide && \
    glide install && \
    go build -o /vault-vouch -v -a -tags netgo -ldflags="-s -w"

FROM scratch

WORKDIR /

COPY --from=builder /vault-vouch .

ENTRYPOINT ["/vault-vouch"]
CMD ["-h"]
