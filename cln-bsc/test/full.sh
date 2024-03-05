#!/bin/bash
shopt -s expand_aliases
pause=55
alias n1-cli="/home/ilya/Code/Cpp/lightning/cli/lightning-cli --lightning-dir=/home/ilya/.lightningd --network=testnet"
alias n2-cli="/home/ilya/Code/Cpp/lightning/cli/lightning-cli --lightning-dir=/home/ilya/HDD/Temp --network=testnet"

export contract_htlc=0x912A96f48965A6ac5480B41732BC12F457EbE535
export contract_token=0x02f4044ed4f3b6fbdbed44d0b0bc58ce8011243e

label=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 3 ; echo '')
json_invoice=$(echo "/tmp/0_n1-hold-${label}-n1-hold-invoice.json")
n1-cli holdinvoice 1000000 $label "blackbox test" > $json_invoice &&
bolt11=$(cat $json_invoice | jq .bolt11 | sed "s/[\'\"]//g") &&
hash=$(cat $json_invoice | jq .payment_hash | sed "s/[\'\"]//g") &&
secret=$(cat $json_invoice | jq .payment_secret | sed "s/[\'\"]//g")
echo "${label}: ${hash} - ${secret}"
n1-cli setbep20htlc 0xfa69445e36862b8fed5bee446bf8072bc03d1b61 $hash $contract_token 1000

echo "Settle LN HOLD Invoice"
json_settled=$(echo "/tmp/${label}-settled.json")
n2-cli pay $bolt11 > $json_settled &
sleep 1
n1-cli holdinvoicesettle $hash | jq .state
sleep 5
preimage=$(cat $json_settled | jq .payment_preimage | sed "s/[\'\"]//g")
echo "Finished ${preimage}"

echo "Wait for ${pause} seconds then redeem"
sleep $pause
echo "${pause} seconds have passed. Redeeming"

echo "Redeeming ${label}: ${hash} - ${secret}, preimage ${preimage}"

n2-cli redeembep20htlc $hash $preimage
