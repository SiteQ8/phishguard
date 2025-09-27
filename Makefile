# filename: Makefile
# Convenience targets for common actions

IMAGE_NAME=phishguard
TAG=latest

.PHONY: build run stop logs bash clean

build:
	docker build -t $(IMAGE_NAME):$(TAG) .

run:
	docker compose up -d --build

stop:
	docker compose down

logs:
	docker compose logs -f

bash:
	docker exec -it phishguard bash

clean:
	docker compose down -v
	docker image rm $(IMAGE_NAME):$(TAG) || true
	docker builder prune -f

