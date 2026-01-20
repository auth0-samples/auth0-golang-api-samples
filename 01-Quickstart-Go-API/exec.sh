#!/usr/bin/env bash
docker build -t auth0-golang-api .
docker run --env-file .env -p 8080:8080 -it auth0-golang-api
