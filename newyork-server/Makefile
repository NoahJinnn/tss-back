.PHONY: run build deploy
APP_NAME=newyork_city
VERSION=latest
IMAGE_NAME=$(APP_NAME):$(VERSION)
LOCAL_DIR=${HOME}/Desktop/$(APP_NAME).tar
SERVER_USER=ubuntu
SERVER_HOST=13.250.230.8
SERVER_DIR=~

run:
	RUST_LOG=info cargo run

# Run docker desktop on Mac first
build:
	DOCKER_BUILDKIT=1 docker build -t newyork_city .

deploy: build
	docker save $(IMAGE_NAME) > $(LOCAL_DIR) && \
	scp $(LOCAL_DIR) $(SERVER_USER)@$(SERVER_HOST):$(SERVER_DIR)
