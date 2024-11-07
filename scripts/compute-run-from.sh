#!/usr/bin/env bash

set -euo pipefail

case "$1" in
  ubuntu*)
    VSN=${1#ubuntu}
    echo "ubuntu:$VSN"
    ;;
  *)
    echo "unsupported OS: $1"
    exit 1
    ;;
esac
