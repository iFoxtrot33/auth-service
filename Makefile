start:
	go run cmd/main.go

start production:
	go run cmd/main.go -config config/production.yml

build:
	go build -o app cmd/main.go

swagger:
	go run github.com/swaggo/swag/cmd/swag init -g cmd/main.go