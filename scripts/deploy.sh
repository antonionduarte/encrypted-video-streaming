#!/bin/bash

cd ..
docker compose build
docker compose up --scale proxy=$1