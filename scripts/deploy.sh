#!/bin/bash

if [ "$#" != "1" ]; then
  echo "Usage: $0 <movie>"
  exit 1
fi

movie=$1

docker-compose build --build-arg MOVIE=$movie
docker-compose up