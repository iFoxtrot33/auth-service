start:
	go run cmd/main.go

start-production:
	go run cmd/main.go -config config/production.yml

build:
	go build -o app cmd/main.go

swagger:
	go run github.com/swaggo/swag/cmd/swag init -g cmd/main.go

docker-build:
	docker-compose -f docker/docker-compose.yml up --build

docker-down:
	docker-compose -f docker/docker-compose.yml down

docker-up:
	docker-compose -f docker/docker-compose.yml up

docker-build-image:
	docker build -t authservice:latest -f docker/Dockerfile .

swarm-deploy: docker-build-image
	docker stack deploy -c docker/docker-compose.yml authservice

swarm-remove:
	docker stack rm authservice