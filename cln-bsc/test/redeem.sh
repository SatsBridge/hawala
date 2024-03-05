#!/bin/bash

alias clg-cli='/home/ilya/Code/Cpp/lightning/cli/lightning-cli --lightning-dir=/home/ilya/.lightningd --network=testnet'

preimage=$(cat invoice.json | jq .payment_secret)
hash=$(cat invoice.json | jq .payment_hash)
clg-cli redeemerc20htlc $preimage $hash
