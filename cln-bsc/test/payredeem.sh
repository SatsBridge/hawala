#!/bin/bash
shopt -s expand_aliases
pause=55
alias n1-cli="/home/ilya/Code/Cpp/lightning/cli/lightning-cli --lightning-dir=/home/ilya/.lightningd --network=testnet"
alias n2-cli="/home/ilya/Code/Cpp/lightning/cli/lightning-cli --lightning-dir=/home/ilya/HDD/Temp --network=testnet"

# 0x0aCBd07e458F228d4869066b998a0F55F36537B2 ERC20 token
# 0xfa69445e36862b8fed5bee446bf8072bc03d1b61 blackbox CLN node / node 2
#clg-cli holdinvoice 1000000 "test0" "blackbox test"

export contract_htlc=0xB62fC95c5E225D8Ae0586c0D3DabACe802D53534
export contract_token=0xE72Ba37AA68A9eb6D5Fad816fC82b5B12Df26429

label=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 3 ; echo '')
json_invoice=$(echo "/tmp/0_n1-bolt11-${label}-n1-invoice.json")
n1-cli invoice 1000000 $label "blackbox test" > $json_invoice &&
bolt11=$(cat $json_invoice | jq .bolt11 | sed "s/[\'\"]//g") &&
hash=$(cat $json_invoice | jq .payment_hash | sed "s/[\'\"]//g") &&
echo "${label}: ${hash}"
n1-cli seterc20htlc 0xfa69445e36862b8fed5bee446bf8072bc03d1b61 $hash $contract_token 1000
sleep $pause
echo "Settle LN Invoice and Redeem at once"
#n2-cli payredeemerc20htlc $bolt11 &
echo "Check Proxy"
curl -X GET http://10.0.0.3:8079/htlc/ping
echo "Request payment $bolt11"
curl -X POST -H "Content-Type: application/json" -d '{"bolt11": "'${bolt11}'", "tx":"some"}'  http://10.0.0.3:8079/htlc/out/set
