#!/bin/bash

./scripts/encrypt-movies.sh
./scripts/gen-movies-integrity-checks.sh
./scripts/encrypt-config.sh $@