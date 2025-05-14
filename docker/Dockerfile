FROM golang:1.23.1 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /go/bin/authservice ./cmd/main.go

FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache libc6-compat gcompat

COPY --from=builder /go/bin/authservice /app/

COPY --from=builder /app/config /app/config

EXPOSE 8082

CMD ["/app/authservice"]