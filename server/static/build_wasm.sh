#!/bin/bash

set -e

cd $(dirname $0)
GOOS=js GOARCH=wasm go build -o cert.wasm
