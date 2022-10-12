#!/bin/bash

docker compose build
docker compose up --scale proxy=$1
