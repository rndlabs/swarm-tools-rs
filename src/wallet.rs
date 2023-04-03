use std::{
    borrow::Borrow,
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use async_trait::async_trait;
use chrono::Utc;
use ethers::{
    abi::{Detokenize, Uint},
    prelude::k256::ecdsa::SigningKey,
    prelude::*,
    types::H160,
    utils::format_units,
};
use eyre::{anyhow, Result};
use passwords::PasswordGenerator;

use crate::{
    chain::{self, ChainConfigWithMeta},
    contracts::{
        foreign_omni_bridge::TokensBridgingInitiatedFilter,
        home_bridge_erc_to_native::AffirmationCompletedFilter,
        home_omni_bridge::TokensBridgedFilter, permittable_token::PermittableToken,
        stake_registry::StakeRegistry, stake_registry::StakesReturn,
    },
    erc20::legacy_permit::Permit,
    exchange,
    game::Game,
    safe::Safe,
    OverlayAddress, WalletArgs, WalletCommands,
};

const CONFIG_DIR: &str = "bees";
const FUNDING_WALLET_KEY: &str = "wallet";
const SAFE_KEY: &str = "safe";

pub async fn process(args: WalletArgs, gnosis_rpc: String) -> Result<()> {
    // Get the config dir and wallet store
    let (config_dir, mut store) = get_cwd_config();
    let gnosis_client = Arc::new(Provider::<Ws>::connect(gnosis_rpc).await?);
    let gnosis_chain = chain::ChainConfigWithMeta::new(gnosis_client.clone()).await?;

    // If the funding wallet doesn't exist, create it
    let funding_wallet = match store.get(FUNDING_WALLET_KEY.to_owned()) {
        Ok(wallet) => wallet,
        Err(_) => {
            println!("Creating funding wallet...");
            let result = store.create_wallet(
                &config_dir,
                None,
                |_key| FUNDING_WALLET_KEY.to_string(),
                |_key| true,
            );

            // If the wallet was created successfully, print the address
            if let Ok((wallet, password)) = result {
                println!(
                    "Funding wallet created: 0x{}",
                    hex::encode(wallet.address())
                );
                println!("Password: {}", password);
            }
            println!();

            let funding_wallet = store.get(FUNDING_WALLET_KEY.to_owned()).unwrap();

            // Use a loop for checking if the user has requested xDAI
            loop {
                // Check if the funding wallet has any xDAI
                let balance = gnosis_client
                    .get_balance(funding_wallet.address(), None)
                    .await?;

                // If the balance is greater than 0.0025, break out of the loop
                match balance > ethers::utils::parse_ether("0.0025")? {
                    true => break,
                    false => {
                        println!("Please visit https://gnosisfaucet.com/ and request some xDAI for the funding wallet. Then press enter to continue...");
                        let mut input = String::new();
                        // Wait for the user to press enter
                        std::io::stdin().read_line(&mut input)?;
                    }
                }
            }

            funding_wallet
        }
    };

    // Remove the funding wallet from the store
    store.remove_wallet(FUNDING_WALLET_KEY.to_string())?;

    // Get the safe address from the config directory
    let safe = match config_dir.join(SAFE_KEY).exists() {
        true => {
            let safe_address =
                H160::from_str(&std::fs::read_to_string(config_dir.join(SAFE_KEY))?)?;

            println!("Loading Safe 0x{}...", hex::encode(safe_address));

            let safe = Safe::load(safe_address, gnosis_client.clone()).await;

            // Check to make sure the funding_wallet is an owner of the safe
            if !safe.is_owner(funding_wallet.address()) {
                return Err(anyhow!("Funding wallet is not an owner of the Safe"));
            }

            safe
        }
        false => {
            println!("Creating Safe...");
            let safe = Safe::new(
                vec![funding_wallet.address()],
                1.into(),
                None,
                gnosis_chain.clone(),
                gnosis_client.clone(),
                funding_wallet.clone(),
            )
            .await;

            println!("Safe created: gno:0x{}", hex::encode(safe.address));

            // Save the safe's address to a file in the config directory
            let safe_file = config_dir.join(SAFE_KEY);
            std::fs::write(safe_file, hex::encode(safe.address))?;

            safe
        }
    };

    println!();

    match args.command {
        WalletCommands::SwapAndBridge {
            mainnet_rpc,
            max_bzz,
            xdai,
        } => {
            let mainnet_chain = chain::ChainConfigWithMeta::new(Arc::new(
                Provider::<Ws>::connect(mainnet_rpc).await?,
            ))
            .await?;
            let xdai_per_wallet = xdai.unwrap_or(ethers::utils::WEI_IN_ETHER);
            let mainnet_signer = SignerMiddleware::new(
                mainnet_chain.client(),
                funding_wallet
                    .clone()
                    .with_chain_id(mainnet_chain.chain_id()),
            );
            let dai_contract = PermittableToken::new(
                mainnet_chain.get_address("DAI_ADDRESS_MAINNET")?,
                mainnet_signer.into(),
            );

            // Load the game and auto-configure the game's topology
            let game = Game::load(&gnosis_chain, None).await?;

            // get all overlays that are not staked
            let overlays = store.unstaked_only(&gnosis_chain).await?;

            // by definition, as all the overlays are unstaked, the total funding
            // is the sum of the average neighborhood stakes.
            let bzz_funding_table = game.calculate_funding(None, &overlays, max_bzz);
            let bzz_req = bzz_funding_table
                .iter()
                .fold(U256::zero(), |acc, (_, amount)| acc + *amount);

            // iterate over total_funding and print the amount of BZZ
            // and XDAI that needs to be funded for each node
            println!();
            println!("Funding table:");
            for (o, amount) in bzz_funding_table.iter() {
                println!("0x{}: {} BZZ", hex::encode(o), format_units(*amount, 16)?);
            }

            // get the total amount of xdai required
            let mut xdai_req = xdai_per_wallet * overlays.len() as u32;

            // make sure the funding wallet has enough xdai
            let funding_wallet_balance = gnosis_client
                .get_balance(funding_wallet.address(), None)
                .await?;
            if funding_wallet_balance < xdai_per_wallet {
                xdai_req += xdai_per_wallet - funding_wallet_balance;
            }

            println!("Total funding required: {} BZZ", format_units(bzz_req, 16)?);
            println!(
                "Total funding required: {} XDAI",
                format_units(xdai_req, 18)?
            );

            let exchange =
                exchange::Exchange::new(mainnet_chain.clone(), funding_wallet.clone()).await?;
            let dai_funding_required = exchange.quote_gross_buy_amount(bzz_req, None).await?;

            // now include the xDAI that is to be bridged as well
            let dai_funding_required = dai_funding_required + xdai_req;

            println!(
                "Total DAI funding required for buying BZZ: {} DAI",
                format_units(dai_funding_required, 18)?
            );

            loop {
                // check if the funding wallet has enough DAI
                let dai_balance = dai_contract
                    .balance_of(funding_wallet.address())
                    .call()
                    .await?;
                match dai_balance < dai_funding_required {
                    true => {
                        println!(
                            "Funding wallet does not have enough DAI to buy BZZ + bridge XDAI"
                        );
                        println!("DAI balance: {} DAI", format_units(dai_balance, 18)?);
                        println!(
                            "DAI required: {} DAI",
                            format_units(dai_funding_required, 18)?
                        );
                        println!();
                        println!(
                            "Please deposit {} DAI to the funding wallet 0x{} and press enter to continue...",
                            format_units(dai_funding_required - dai_balance, 18)?,
                            hex::encode(funding_wallet.address())
                        );
                        let mut input = String::new();
                        // Wait for the user to press enter
                        std::io::stdin().read_line(&mut input)?;
                    }
                    false => break,
                }
            }

            println!();

            // save the current gnosis block number
            let last_block = gnosis_client.get_block_number().await?;

            // now that we have enough DAI, the first thing we need to do is to bridge the xDAI
            let handler = crate::wallet::CliTransactionHandler::new(
                funding_wallet.clone(),
                dai_contract.transfer(mainnet_chain.get_address("XDAI_BRIDGE")?, xdai_req),
                format!(
                    "Bridging {} XDAI to funding wallet",
                    format_units(xdai_req, 18)?
                ),
            );

            // This contains the initiator transaction hash for the bridging of the xDAI
            // We monitor for the `tx hash` event on the xDAI chain to know when the bridging is complete
            let dai_bridge_receipt = handler.handle(&mainnet_chain, 1).await?;

            println!();

            // This contains the message id for the bridging of the BZZ
            // We monitor for the `message id` on the xDAI chain to know when the bridging is complete
            let bzz_bridge_receipt = exchange
                .buy_and_bridge_bzz(bzz_req, None, Some(safe.address()))
                .await?;

            // iterate over the logs to find the TokensBridgingInitiated event
            let bzz_bridging = bzz_bridge_receipt
                .logs
                .iter()
                .find_map(|log| {
                    match log.address == mainnet_chain.get_address("OMNI_BRIDGE").unwrap() {
                        true => {
                            let e = ethers::contract::parse_log::<TokensBridgingInitiatedFilter>(
                                log.clone(),
                            )
                            .unwrap();
                            Some(e)
                        }
                        false => None,
                    }
                })
                .unwrap();

            println!();
            println!(
                "DAI bridging initiated with tx hash: 0x{}",
                hex::encode(dai_bridge_receipt.transaction_hash)
            );
            let (explorer_name, explorer_url) =
                mainnet_chain.bridge_explorer_url(dai_bridge_receipt.transaction_hash);
            println!(
                "Monitor the DAI bridging status at the {}: {}",
                explorer_name, explorer_url
            );
            println!(
                "BZZ bridging initiated with message id: 0x{}",
                hex::encode(bzz_bridging.message_id)
            );
            let (explorer_name, explorer_url) =
                mainnet_chain.bridge_explorer_url(bzz_bridge_receipt.transaction_hash);
            println!(
                "Monitor the BZZ bridging status at the {}: {}",
                explorer_name, explorer_url
            );

            // From here we need to wait for the bridging to complete
            let addresses = vec![
                gnosis_chain.get_address("XDAI_BRIDGE")?,
                gnosis_chain.get_address("OMNI_BRIDGE")?,
            ];
            let filter = Filter::new().address(addresses).from_block(last_block);
            let mut stream = gnosis_client.subscribe_logs(&filter).await?;

            // Wait for the bridging to complete
            let mut num_transactions = 2;
            while let Some(log) = stream.next().await {
                match log.address {
                    // BZZ bridge
                    a if a == gnosis_chain.get_address("OMNI_BRIDGE")? => {
                        let t = parse_log::<TokensBridgedFilter>(log.clone());
                        if let Ok(t) = t {
                            if t.message_id == bzz_bridging.message_id {
                                assert_eq!(t.recipient, safe.address());
                                assert_eq!(t.value, bzz_req);
                                println!("BZZ bridging completed!!");
                                num_transactions -= 1;
                            }
                        }
                    }
                    // DAI bridge
                    a if a == gnosis_chain.get_address("XDAI_BRIDGE")? => {
                        let e = parse_log::<AffirmationCompletedFilter>(log.clone());
                        if let Ok(e) = e {
                            if e.transaction_hash
                                == dai_bridge_receipt.transaction_hash.to_fixed_bytes()
                            {
                                assert_eq!(e.recipient, funding_wallet.address());
                                println!("DAI bridging completed!!");
                                num_transactions -= 1;
                            }
                        }
                    }
                    _ => {}
                }
                if num_transactions == 0 {
                    break;
                }
            }

            // Now that the bridging is complete, we can distribute the BZZ and xDAI to the nodes
            // To do this, we will create all the transactions and then execute them in a batch
            // This will save us a lot of gas. We do this by iterating over the bzz_funding_table
            // and creating a transaction for each node. We then execute the batch transaction
            // with the Safe
            distribute_funds(
                &gnosis_chain,
                &safe,
                &store,
                &bzz_funding_table,
                xdai_per_wallet,
                &funding_wallet,
            )
            .await?;

            // Next we need to set allowances:
            // 1. The Safe needs to be able to spend the BZZ
            // 2. The StakeRegistry needs to be able to spend the BZZ
            let other_spenders = vec![(
                "StakeRegistry".to_string(),
                gnosis_chain.get_address("STAKE_REGISTRY").unwrap(),
            )];

            batch_approve(
                &gnosis_chain,
                &safe,
                &store,
                gnosis_chain.get_address("BZZ_ADDRESS_GNOSIS")?,
                other_spenders,
                &funding_wallet,
            )
            .await?;

            // Confirm if the user wants to stake the nodes
            let mut input = String::new();
            print!("Are you sure you want to stake all the nodes? [y/N]: ");
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() != "y" {
                std::process::exit(0);
            }

            stake_all(&gnosis_chain, &store, &bzz_funding_table).await
        }
        WalletCommands::DistributeFunds { max_bzz, xdai } => {
            let game = Game::load(&gnosis_chain, None).await?;
            let overlays = store.unstaked_only(&gnosis_chain).await?;
            let bzz_funding_table = game.calculate_funding(None, &overlays, max_bzz);
            let xdai_per_wallet = xdai.unwrap_or(ethers::utils::WEI_IN_ETHER);

            distribute_funds(
                &gnosis_chain,
                &safe,
                &store,
                &bzz_funding_table,
                xdai_per_wallet,
                &funding_wallet,
            )
            .await?;
            Ok(())
        }
        WalletCommands::PermitApproveAll { token } => {
            let other_spenders = vec![(
                "StakeRegistry".to_string(),
                gnosis_chain.get_address("STAKE_REGISTRY").unwrap(),
            )];

            batch_approve(
                &gnosis_chain,
                &safe,
                &store,
                token.unwrap_or(gnosis_chain.get_address("BZZ_ADDRESS_GNOSIS").unwrap()),
                other_spenders,
                &funding_wallet,
            )
            .await?;

            Ok(())
        }
        WalletCommands::SweepAll { token } => {
            // Connect to the BZZ token contract
            let contract = PermittableToken::new(
                token.unwrap_or(gnosis_chain.get_address("BZZ_ADDRESS_GNOSIS")?),
                gnosis_client.clone(),
            );

            // Get all the bee node wallets from the store
            // iterate over them and call transfer on the BZZ token for each one
            let wallets = store.get_all();

            let mut multicall = Multicall::<Provider<Ws>>::new(gnosis_chain.client(), None).await?;

            // iterate through the wallets and get their balances
            for (_, wallet) in wallets.iter() {
                multicall.add_call(contract.balance_of(wallet.address()), false);
            }
            let balances: Vec<U256> = multicall.call_array().await?;

            let mut description = "Sweeping funds from nodes to Safe:".to_string();
            let mut txs: Vec<Bytes> = Vec::new();
            // balances and wallets are in the same order
            // iterate over the wallets, and if the balance is greater than 0 use transferFrom to
            // transfer the balance to the safe
            for (i, balance) in balances.iter().enumerate() {
                // TODO: if *balance > 0.into() {
                let wallet = &wallets[i].1;
                let transfer = contract.transfer_from(wallet.address(), safe.address(), *balance);
                txs.push(transfer.calldata().unwrap());
                description = format!(
                    "{}\n - {} ({})",
                    description,
                    wallets[i].0,
                    format_units(*balance, 16)?
                );
                // }
            }

            let _receipt = safe
                .exec_batch_tx(
                    txs.into_iter()
                        .map(|tx| {
                            (
                                crate::safe::OPERATION_CALL,
                                contract.address(),
                                U256::from(0),
                                tx,
                            )
                        })
                        .collect(),
                    0.into(),
                    description,
                    &gnosis_chain,
                    &funding_wallet,
                    1.into(),
                )
                .await?;

            Ok(())
        }
        WalletCommands::StakeAll => {
            let game = Game::load(&gnosis_chain, None).await?;
            let overlays = store.unstaked_only(&gnosis_chain).await?;
            let bzz_funding_table = game.calculate_funding(None, &overlays, None);

            // Confirm if the user wants to stake the nodes
            let mut input = String::new();
            print!("Are you sure you want to stake all the nodes? [y/N]: ");
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() != "y" {
                std::process::exit(0);
            }

            stake_all(&gnosis_chain, &store, &bzz_funding_table).await
        }
    }
}

/// A private function that will approve the safe to spend the tokens on behalf of the wallets
/// This function will be called by the safe owner. It will iterate over the wallets in the store
/// and generate the permit and approve calldata for each one.
/// TODO: This function should be refactored to use the Multicall contract to check for existing
/// approvals and only generate the calldata for the ones that need it.
async fn batch_approve<M>(
    chain: &ChainConfigWithMeta<M>,
    safe: &Safe<M>,
    store: &WalletStore,
    token: Address,
    other_spenders: Vec<(String, Address)>,
    wallet: &Wallet<SigningKey>,
) -> Result<TransactionReceipt>
where
    M: Middleware + Clone + 'static,
{
    let mut batch: Vec<(u8, Address, U256, Bytes)> = Vec::new();
    let contract = PermittableToken::new(token, chain.client());

    let wallets = store.get_all();
    let symbol = contract.symbol().call().await?;

    // Push the safe address onto the front of the other spenders
    let mut spenders = other_spenders;
    spenders.insert(0, ("Safe".to_string(), safe.address()));

    let mut description = format!("Batch approve spending of {} tokens:\n - Spenders:", symbol);
    for (name, _) in &spenders {
        description = format!("{}\n   - {}", description, *name);
    }

    description = format!("{}\n - Wallets:", description);

    // iterate through the wallets and approve the spenders
    for (name, wallet) in wallets {
        description = format!("{}\n   - {}", description, name);

        // Process the permit and approve for each spender
        for (i, (_, spender)) in spenders.iter().enumerate() {
            // First do the permit for the spender to spend the tokens
            let permit = Permit::new(
                wallet.address(),
                *spender,
                Some(U256::from(i)),
                U256::from(Utc::now().timestamp() as u32 + 60 * 30),
                true,
                chain.client(),
                token,
            )
            .await
            .unwrap();

            let signature = permit
                .sign(wallet.clone(), chain.client(), token, None)
                .await?;

            let permit_calldata = permit
                .permit_calldata(signature, chain.client(), token)
                .await?;

            batch.push((
                crate::safe::OPERATION_CALL,
                token,
                U256::from(0),
                permit_calldata,
            ));
        }
    }

    safe.exec_batch_tx(batch, 0.into(), description, chain, wallet, 1.into())
        .await
}

async fn stake_all<M>(
    chain: &ChainConfigWithMeta<M>,
    store: &WalletStore,
    bzz_funding_table: &Vec<([u8; 32], U256)>,
) -> Result<()>
where
    M: Middleware + Clone + 'static,
{
    // take advantage of the fact that only nodes in the funding table are to be staked
    // should spawn a future for each node's staking
    // then wait for all futures to complete

    let addr = chain.get_address("STAKE_REGISTRY").unwrap();

    let mut handles = Vec::new();
    for (o, amount) in bzz_funding_table {
        let overlay = hex::encode(o);
        let amount = *amount;
        let wallet = store.get(overlay.clone()).unwrap();
        let signer = SignerMiddleware::new(
            chain.client(),
            wallet.clone().with_chain_id(chain.chain_id()),
        );
        // use tokio to spawn new tasks
        let future = tokio::spawn(async move {
            println!(
                "Staking {} BZZ for {}",
                format_units(amount, 16).unwrap(),
                overlay
            );
            let contract = StakeRegistry::new(addr, signer.into());
            let call = contract.deposit_stake(wallet.address(), [0u8; 32], amount);
            let tx = call.send().await.unwrap();

            // Wait for the transaction to be mined
            tx.await.unwrap()
        });
        handles.push(future);
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    for (i, receipt) in results.iter().enumerate() {
        let (explorer, url) = chain.explorer_url(receipt.clone().unwrap().transaction_hash);
        println!(
            "Staking for {} completed, see {}: {}",
            hex::encode(bzz_funding_table[i].0),
            explorer,
            url
        );
    }

    Ok(())
}

/// A private function that will distribute the funds from the safe to the bee nodes
/// This function will be called by the safe owner
/// It will iterate over the wallets in the store and call transfer on the BZZ token
/// for each one
async fn distribute_funds<M>(
    chain: &ChainConfigWithMeta<M>,
    safe: &Safe<M>,
    store: &WalletStore,
    bzz_funding_table: &Vec<([u8; 32], ethers::types::U256)>,
    xdai_per_wallet: U256,
    wallet: &Wallet<SigningKey>,
) -> Result<TransactionReceipt>
where
    M: Middleware + Clone + 'static,
{
    let mut batch: Vec<(u8, Address, U256, Bytes)> = Vec::new();
    let xbzz = PermittableToken::new(
        chain.get_address("BZZ_ADDRESS_GNOSIS").unwrap(),
        chain.client(),
    );
    let mut description = "Distribute BZZ and xDAI to nodes:".to_string();
    for (node, bzz) in bzz_funding_table {
        let node = store.get_address(hex::encode(node))?;

        if xdai_per_wallet > 0.into() {
            // Transfer the xDAI to the node
            batch.push((
                0, // call
                node,
                xdai_per_wallet,
                Bytes::new(),
            ));
            description.push_str(&format!(
                "\n - {} xDAI to 0x{}",
                format_units(xdai_per_wallet, 18)?,
                hex::encode(node)
            ));
        }

        // Transfer the BZZ to the node
        batch.push((
            0, // call
            xbzz.address(),
            0.into(),
            xbzz.transfer(node, *bzz).calldata().unwrap(),
        ));
        description.push_str(&format!(
            "\n - {} BZZ to 0x{}",
            format_units(*bzz, 16)?,
            hex::encode(node)
        ));
    }

    safe.exec_batch_tx(
        batch,
        xdai_per_wallet * bzz_funding_table.len(),
        description,
        chain,
        wallet,
        1.into(),
    )
    .await
}

/// A transaction handler for sending transactions
pub struct CliTransactionHandler<B, M, D, S>
where
    B: Borrow<SignerMiddleware<Arc<M>, S>> + Clone,
    M: Middleware + 'static,
    D: Detokenize,
    S: Signer,
{
    wallet: Wallet<SigningKey>,
    call: FunctionCall<B, SignerMiddleware<Arc<M>, S>, D>,
    description: String,
}

impl<B, M, D, S> CliTransactionHandler<B, M, D, S>
where
    B: Borrow<SignerMiddleware<Arc<M>, S>> + Clone,
    M: Middleware + 'static,
    D: Detokenize,
    S: Signer,
{
    /// Create a new transaction handler
    pub fn new(
        wallet: Wallet<SigningKey>,
        call: FunctionCall<B, SignerMiddleware<Arc<M>, S>, D>,
        description: String,
    ) -> Self {
        Self {
            wallet,
            call,
            description,
        }
    }

    /// Handle the CLI prompt for sending a transaction
    pub async fn handle(
        &self,
        chain: &chain::ChainConfigWithMeta<M>,
        num_confirmations: usize,
    ) -> Result<TransactionReceipt>
    where
        M: Middleware + Clone + 'static,
    {
        let client = chain.client();

        // Get the gas estimate and gas price
        let gas_limit = match self.call.estimate_gas().await {
            Ok(gas_limit) => gas_limit,
            Err(err) => {
                println!("Error estimating gas: {}", err);
                std::process::exit(1);
            }
        };
        let gas_price = client.get_gas_price().await?;

        // Calculate the total gas cost
        let gas_cost = gas_limit * gas_price;

        // Get the balance of the wallet
        let balance = client.get_balance(self.wallet.address(), None).await?;

        // If the balance is less than gas cost, print an error and return
        // Tell them how much to fund the wallet with
        if balance < gas_cost {
            println!(
                "Insufficient funds to send transaction. Please fund the wallet with at least {} {}",
                format_units(gas_cost, "ether")?,
                chain.native_units()
            );
            std::process::exit(1);
        }

        // Display the transaction details
        println!("{}:", self.description);
        // blank line
        println!();
        println!("Transaction Details:");
        println!("  From: 0x{}", hex::encode(self.wallet.address()));
        println!(
            "  To: 0x{}",
            hex::encode(self.call.tx.to().unwrap().as_address().unwrap())
        );
        println!("  Value: {}", self.call.tx.value().unwrap_or(&U256::zero()));
        println!("  Data: 0x{}", hex::encode(self.call.tx.data().unwrap()));
        println!("  Gas Limit: {}", gas_limit);
        println!("  Gas Price: {}", format_units(gas_price, "gwei")?);
        println!("  Gas Cost: {}", format_units(gas_cost, "ether")?);
        println!();

        // Confirm with the user that they want to send the transaction
        let mut input = String::new();
        print!("Send transaction? [y/N]: ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            std::process::exit(0);
        }

        // Set the gas limit and gas price
        // This is done after the confirmation prompt so that the user can see the gas cost
        // dev: we clone the call here because we're mutating it
        let call = self.call.clone().gas(gas_limit).gas_price(gas_price);

        // Send the transaction
        let tx = call.send().await;

        // If the transaction failed to send, print an error and return
        if let Err(err) = tx {
            // if the error message contains "insufficient funds", print a more helpful message
            if err.to_string().contains("insufficient funds") {
                println!("Insufficient funds to send transaction. Please fund the wallet with at least {} {}", ethers::utils::format_units(gas_cost, "ether").unwrap(), chain.native_units());
            } else {
                println!("Error sending transaction: {}", err);
            }
            std::process::exit(1);
        }

        // Get the transaction hash
        let tx = tx.unwrap();

        // Print the URL to the transaction on the block explorer
        let (explorer, url) = chain.explorer_url(tx.tx_hash());

        // Print URL to the transaction on the block explorer
        println!("Submitting the transaction to {}: {}", explorer, url);

        // Waiting for the transaction to be mined
        print!(
            "Waiting for the transaction to be mined (waiting for {} confirmations)...",
            num_confirmations
        );
        let receipt = tx.confirmations(num_confirmations).await?.unwrap();

        // if the transaction failed, print an error and return
        if receipt.status == Some(0.into()) {
            println!("Transaction failed. See the transaction on the block explorer for more details: {}", url);
            std::process::exit(1);
        }

        // If we made it this far, the transaction was successful
        println!("successful!");

        Ok(receipt)
    }
}

/// A wallet store
/// This is a collection of wallets that can be used to sign transactions
pub struct WalletStore {
    path: PathBuf,
    wallets: HashMap<String, Wallet<SigningKey>>,
    pg: PasswordGenerator,
}

impl WalletStore {
    /// Load a wallet store from the given path
    pub fn load(path: PathBuf) -> Result<Self> {
        // The path should be a directory
        if !path.is_dir() {
            // create the directory if it doesn't exist
            std::fs::create_dir_all(path.clone()).unwrap();
        }

        // Create a new wallet store
        let mut store = Self {
            path: path.clone(),
            wallets: HashMap::new(),
            pg: PasswordGenerator {
                length: 32,
                numbers: true,
                lowercase_letters: true,
                uppercase_letters: true,
                symbols: false,
                spaces: false,
                exclude_similar_characters: true,
                strict: true,
            },
        };

        // Iterate over all the files in the directory. Any .json files are assumed to be keystore files
        for entry in path.read_dir()? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().unwrap_or_default() == "json" {
                store.load_wallet(&path)?;
            }
        }

        Ok(store)
    }

    /// Load a wallet from a keystore file
    /// The password is assumed to be in a file with the same name as the keystore but with a .password extension
    /// The wallet name is assumed to be the file name without the extension
    pub fn load_wallet(&mut self, path: &Path) -> Result<()> {
        // We assume that the path is a file to the encrypted keystore
        if !path.is_file() {
            return Err(anyhow!("Invalid keystore path"));
        }

        // The password to load the keystore is in the file with the same name as the keystore but with a .password extension
        let password_path = path.with_extension("password");
        if !password_path.is_file() {
            return Err(anyhow!("Password file not found"));
        }

        // Load the password from the file
        std::fs::read_to_string(password_path)
            .map_err(|e| anyhow!("Failed to read password file: {}", e))
            .and_then(|password| {
                // Load the wallet from the keystore
                let wallet = LocalWallet::decrypt_keystore(path, password)?;
                // Get the wallet name from the file name (strip the extension)
                let name = path.file_stem().unwrap().to_str().unwrap().to_string();

                println!("Loaded wallet: {}", name);

                // Add the wallet to the store
                self.wallets.insert(name, wallet);
                Ok(())
            })
    }

    /// Insert a wallet into the store
    pub fn insert_wallet(&mut self, name: String, wallet: Wallet<SigningKey>) -> Result<()> {
        if self.wallets.contains_key(&name) {
            return Err(anyhow!("Wallet already exists"));
        }

        self.wallets.insert(name, wallet);
        Ok(())
    }

    pub fn remove_wallet(&mut self, name: String) -> Result<()> {
        if !self.wallets.contains_key(&name) {
            return Err(anyhow!("Wallet not found"));
        }

        self.wallets.remove(&name);
        Ok(())
    }

    /// Get a wallet by its name
    pub fn get(&self, name: String) -> Result<Wallet<SigningKey>> {
        match self.wallets.get(&name) {
            Some(wallet) => Ok(wallet.clone()),
            None => Err(anyhow!("Wallet not found")),
        }
    }

    /// Get the address of a wallet by its name
    pub fn get_address(&self, name: String) -> Result<H160> {
        self.get(name).map(|wallet| wallet.address())
    }

    /// Get the name of a wallet by its address
    pub fn get_name(&self, address: H160) -> Result<String> {
        for (name, wallet) in self.wallets.iter() {
            if wallet.address() == address {
                return Ok(name.clone());
            }
        }

        Err(anyhow!("Wallet not found"))
    }

    /// Get all the wallets in the store
    /// This returns a vector of tuples containing the wallet name and the wallet
    /// The wallets are sorted by name
    pub fn get_all(&self) -> Vec<(String, Wallet<SigningKey>)> {
        let mut wallets: Vec<(String, Wallet<SigningKey>)> = self
            .wallets
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        wallets.sort_by(|a, b| a.0.cmp(&b.0));
        wallets
    }

    /// Create a new wallet
    /// If the password is not provided, a random one will be generated
    /// The name of the wallet will be generated by the name function
    /// The wallet will be verified by the verify function
    /// If the wallet is not verified, the wallet will not be created
    /// The wallet will be saved to the path provided
    pub fn create_wallet<F, N>(
        &mut self,
        path: &Path,
        password: Option<String>,
        name: N,
        verify: F,
    ) -> Result<(Wallet<SigningKey>, String)>
    where
        F: FnOnce(Wallet<SigningKey>) -> bool,
        N: FnOnce(Wallet<SigningKey>) -> String,
    {
        // If the password is not provided, generate a random one
        let password = match password {
            Some(password) => password,
            None => self.pg.generate_one().unwrap(),
        };

        // create a new keystore with the password
        let (wallet, uuid) =
            LocalWallet::new_keystore(path, &mut rand::thread_rng(), password.clone(), None)?;

        // Verify the wallet
        if !verify(wallet.clone()) {
            return Err(anyhow!("Wallet verification failed"));
        }

        // Get the name of the wallet
        let name = name(wallet.clone());

        let keystore_path = path.join(uuid);
        let new_keystore_path = self.path.join(format!("{}.json", name));
        println!(
            "{} -> {}",
            keystore_path.display(),
            new_keystore_path.display()
        );
        std::fs::copy(keystore_path, new_keystore_path)?;

        // Save the password to the wallet store path
        let password_path = self.path.join(format!("{}.password", name));
        std::fs::write(password_path, password.clone())?;

        // Add the wallet to the wallet store
        self.insert_wallet(name, wallet.clone())?;

        // return the path to the keystore and the password
        Ok((wallet, password))
    }
}

#[async_trait]
pub trait OverlayStore<M>
where
    M: Middleware + Clone + 'static,
{
    fn get_overlays(&self) -> Vec<OverlayAddress>;
    async fn unstaked_only(&self, chain: &ChainConfigWithMeta<M>) -> Result<Vec<OverlayAddress>>;
}

#[async_trait]
impl<M> OverlayStore<M> for WalletStore
where
    M: Middleware + Clone + 'static,
{
    fn get_overlays(&self) -> Vec<OverlayAddress> {
        self.wallets
            .keys()
            .map(|o| hex::decode(o).unwrap().try_into().unwrap())
            .collect()
    }

    async fn unstaked_only(&self, chain: &ChainConfigWithMeta<M>) -> Result<Vec<OverlayAddress>> {
        let wallets = self.get_all();
        let stake_registry =
            StakeRegistry::new(chain.get_address("STAKE_REGISTRY")?, chain.client());

        let mut multicall = Multicall::<M>::new(chain.client(), None).await?;
        for (o, _) in &wallets {
            let overlay = hex::decode(o).unwrap().try_into().unwrap();
            multicall.add_call(stake_registry.stakes(overlay), false);
        }

        let results: Vec<StakesReturn> = multicall.call_array().await?;

        let mut unstaked = vec![];
        for (i, (o, _)) in wallets.into_iter().enumerate() {
            if results[i].stake_amount == Uint::zero() {
                unstaked.push(hex::decode(o).unwrap().try_into().unwrap());
            }
        }

        Ok(unstaked)
    }
}

/// Get the default configuration directory and the wallet store
fn get_cwd_config() -> (PathBuf, WalletStore) {
    let path = PathBuf::from(".");
    let store_dir = path.join(CONFIG_DIR);

    let store = WalletStore::load(store_dir.clone()).unwrap();

    (store_dir, store)
}
