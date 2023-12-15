#!/bin/bash

#Variant
#export SEED="[put your 12 words seed phrase here]"
#export URL="wss://ws.test.azero.dev"

NODE_URL="${NODE_URL:-ws://localhost:9944}"
AUTHORITY="${AUTHORITY:-//Alice}"

cargo contract build --release --quiet 1>&2
cargo contract instantiate \
      --url "$NODE_URL" --suri "$AUTHORITY" --skip-confirm --output-json | jq -r ".contract"
