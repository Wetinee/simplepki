#!/bin/bash

set -e
cd $(dirname $0)

GOOS=js GOARCH=wasm go build -o cert.wasm
cp $(go env GOROOT)/misc/wasm/wasm_exec.js ./
