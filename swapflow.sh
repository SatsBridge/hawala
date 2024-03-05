#!/bin/bash
shopt -s expand_aliases
pause=55
alias n1-cli="/home/ilya/Code/Cpp/lightning/cli/lightning-cli --lightning-dir=/home/ilya/.lightningd --network=testnet"
alias n2-cli="/home/ilya/Code/Cpp/lightning/cli/lightning-cli --lightning-dir=/home/ilya/HDD/Temp --network=testnet"

export contract_htlc=0x912A96f48965A6ac5480B41732BC12F457EbE535
export contract_token=0x02f4044ed4f3b6fbdbed44d0b0bc58ce8011243e

label=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 3 ; echo '')
json_invoice=$(echo "/tmp/0_n1-${label}-n1-invoice.json")
n2-cli invoice 1000000 $label "hawala test" > $json_invoice &&
bolt11=$(cat $json_invoice | jq .bolt11 | sed "s/[\'\"]//g") &&
hash=$(cat $json_invoice | jq .payment_hash | sed "s/[\'\"]//g")
echo "Invoice ${label}, hash ${hash}. Creating order"
n2-cli bscsettokenhtlc 0xfa69445e36862b8fed5bee446bf8072bc03d1b61 $hash $contract_token 1000
n2-cli hawala-create "{\"asset\": \"D18\", \"price\": 999, \"hashlock\": \"${hash}\"}"
echo "Visit https://testnet.bscscan.com/address/0x912a96f48965a6ac5480b41732bc12f457ebe535 for updates"
sleep 10
echo "Taking the order"
n1-cli hawala-take $hash
echo "See logs"
#json_settled=$(echo "/tmp/${label}-settled.json")
#n2-cli pay $bolt11 > $json_settled &
#sleep 5
#preimage=$(cat $json_settled | jq .payment_preimage | sed "s/[\'\"]//g")
