# swarm-tools-rs

This repository contains the source code for `swarm-tools-rs`, providing efficient, highly performant tools for interacting / calculating primitives used by [Swarm](https://ethswarm.org).

Capabilities available within include:

1. Topology calculator 

    a. Given a storage radius, dump out the base overlay for all neighbourhoods.
    b. Given a storage radius, calculate the number of neighbourhoods.
    
2. Overlay calculator / miner

    a. Given an ethereum address, network ID, and optional nonce, calculate the overlay address.
    b. Given a storage radius and target neighbourhood, mine an ethereum address into the specified neighbourhood.
    c. Given an overlay address and a storage radius, calculate the neighbourhood.

3. Schelling game analysis

    a. Given a storage radius, dump statistics for all staked neighbourhoods.

4. Postage stamp analysis

    a. Dump out all the current stamps an provide a statistical overview including current data storage paid for.

5. Funding tools

    a. Using DAI on Mainnet, convert the required amount to BZZ and bridge DAI / BZZ to Gnosis Chain.
    b. Using xBZZ / xDAI on Gnosis Chain, fund nodes.
    c. Batch ERC20 approvals for all nodes.
    d. Batch ERC20 transfers for sweeping profits from all nodes.
    e. Stake all nodes.

## Usage

```bash
swarm-tools --help
```