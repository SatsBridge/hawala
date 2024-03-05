#!/bin/bash

alias clg-cli='/home/ilya/Code/Cpp/lightning/cli/lightning-cli --lightning-dir=/home/ilya/.lightningd --network=testnet'

# 0x0aCBd07e458F228d4869066b998a0F55F36537B2 ERC20 token
# 0xfa69445e36862b8fed5bee446bf8072bc03d1b61 blackbox CLN node
#clg-cli holdinvoice 1000000 "test0" "blackbox test"
clg-cli holdinvoice 1000000 "test0" "blackbox test" > invoice.json
preimage=$(cat invoice.json | jq .payment_secret) && hash=$(cat invoice.json | jq .payment_hash)

clg-cli seterc20htlc 0xfa69445e36862b8fed5bee446bf8072bc03d1b61 $hash 0x0aCBd07e458F228d4869066b998a0F55F36537B2 0.1


clg-cli redeemerc20htlc 2a7d80ea52246634ffefdac26655b8189bd49acc9069791a378e166698658e0f d2b30b5a429f8c610ef176b4d9021cf8076f82bd00de59e11502bd8d4220ff73

,
