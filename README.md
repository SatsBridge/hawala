# Aleph Hawala

MVP of the decentralized exchange built on top of the Bitcoin Lightning Network and Aleph Zero protocol. The exchanges are facilitated in a combined off-chain/on-chain fashion where an off-chain part functions via settlement through Bitcoin payment channels, and smart contracts drive an on-chain part.

Aleph Hawala resembles the Robosats project by its deal flow while avoiding Robosats centralized structure. It is closer to Bisq and similarly allows operations behind the Tor for enhanced privacy and censorship resistance, though it lacks proper market coordination. Secure and scalable ways for organizing coordinated Cybill-resistant order books or price oracles should be researched separately.

As a protocol with fast blocks and nearly instant settlement, Aleph Zero allows faster trades to be achieved. The DEX may benefit from enhanced privacy, albeit its features weren't investigated in full due to limited time.

## How it works

We put a top-level scheme on the diagram below. Each market participant runs a self-hosted, self-custodial Lightning Network node with at least one channel open to the external network or potential counterparty.

```
        ┌───────────┐
        │           │
        │           │
        │           │    Post Order
        │   Node 1  │ ──────────────────────┐
        │           │                       ▼
        │           │              ┌─────────────────┐
        │           │              │                 │
        └──┬────────┘              │                 │
           │     ▲                 │  Smart Contract │
           │     │                 │                 │
LN Payment │     │  Quote          │  - hashlock     │
           │     │                 │                 │
           ▼     │                 │  - expiration   │
        ┌────────┴──┐              │                 │
        │           │              │                 │
        │           │  Withdrawal  └────┬────────────┘
        │           │                   │   ▲
        │   Node 2  │ ◄─────────────────┘   │
        │           │       Preimage        │
        │           │ ──────────────────────┘
        │           │
        └───────────┘
```

The Aleph Hawala plugin loads along with other Core Lightning plugins and enables the user's node to connect and interact with the Aleph Zero network.

### Seller flow

An asset Seller locks coins in the smart contract with hashlock and expiration date. After expiration, coins may be redeemed by the Seller, and the Buyer must check if she has a safe margin until the expiration block (date) approaches.

### Buyer flow

In the simplest case, the Buyer exchanges tokenized Bitcoins for off-chain satoshis; therefore, the price might be equal to 1, and the price negotiation step may be avoided. For a more general approach, let's consider two different assets that do not even have a nominal resemblance. Therefore, a buyer needs to offer a price for an asset.

Peers agree upon the price in an off-chain fashion via custom onion messages. A particular protocol for onion messages makes it possible to send price offers to any node in the network. However, an MVP is limited by directly connected peers. Additionally, no direct negotiation process may occur if market limit orders are posted as Nostr events and coordinated via Nostr relayers. After achieving agreement the Buyer receives Lightning invoice.

When parsing Lightning invoice, the Buyer obtains payment hash and compares it against offers for coins locked onchain. Invoice amount and an amount of coins of specific asset result in particular price which the buyer also checks, after confirming that some coins locked by payment hash and the negotiated price, the Buyer sends payment and receives payment preimage that unlocks coins in the contract.

## Prerequisites

The Aleph Zero plugin requires Core Lightning node `v23.08` to be installed. Please avoid using the mainnet configuration. It is advisable to run `btcli4j` since the standard `bcli` plugin leads to bugs in channel management.

## How to build

Issuing `cargo build` builds the plugin binary `./target/debug/cln-aleph`, which should be added as a parameter for the `--plugin` option. The example is given below:

```
./lightningd/lightningd --plugin=<ALEPH PLUGIN DIR>/target/debug/cln-aleph
```

Besides that, further options must be added to the Core Lightning node `config` file:

```
aleph-worker-sleep=30
aleph-host=ws://0.0.0.0:9944
```

## ToDo's

There are plenty of issues which should be addressed before going mainnet. Some of them require asking for help from Aleph Zero node developers.

[ ] Resolve the issue with the Testnet node
[ ] Move onto another substrate client - adopt code from the Aleph node project
[ ] Re-use test code from Aleph node for better smart-contract and network interactions
[ ] Implement Type-Lenght-Value codec for custom LN messages
[ ] Add codec for asset quotes & order book
[ ] Finalize basic ink! HTLC contract. Add redeem & refund functions and tests.
[ ] Consider other options for Decentralized exchange smart-contracts

