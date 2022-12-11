#!/bin/bash

mvn clean compile assembly:single
docker compose build
docker compose up