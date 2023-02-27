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

## Usage

```bash
swarm-tools --help
```