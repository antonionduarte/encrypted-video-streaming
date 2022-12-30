#!/bin/bash

mvn clean compile assembly:single
./scripts/deploy.sh $@