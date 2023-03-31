use crate::{contracts, chain::ChainConfigWithMeta};
use eyre::Result;
use ethers::{
    prelude::k256::ecdsa::SigningKey,
    prelude::*,
};

pub struct Exchange<M> 
where
    M: Middleware,
{
    contract: contracts::exchange::Exchange<M>,
    curve: contracts::curve::Curve<M>,
    wallet: Wallet<SigningKey>,
    // The fee is in basis points (1/100th of a percent)
    fee_bps: u32,
}

impl<M: Middleware + 'static> Exchange<M> {
    pub async fn new(chain: ChainConfigWithMeta<M>, wallet: Wallet<SigningKey>) -> Exchange<M> 
    {
        let contract = contracts::exchange::Exchange::new(
            chain.get_address("OPENBZZ_EXCHANGE").unwrap(),
            chain.client(),
        );
        let curve = contracts::curve::Curve::new(
            chain.get_address("BONDING_CURVE").unwrap(),
            chain.client(),
        );
        let fee_bps = contract.fee().call().await.unwrap();
        Self { contract, curve, wallet, fee_bps: fee_bps.as_u32() }
    }

    /// Given a required amount of BZZ, determine the amount of DAI that needs to be sent to the exchange
    /// contract to receive the required amount of BZZ.
    /// This is done by calling the `curve` contract's `getBuyAmount` function.
    /// The amount returned includes the fee and any slippage.
    pub async fn get_gross_buy_amount(&self, amount: U256, slippage_bps: Option<u32>) -> Result<U256> {
        // Get the amount of DAI required to buy the required amount of BZZ
        let amount = self.curve.buy_price(amount).call().await?;

        // Add the fee and slippage
        let fee = amount * self.fee_bps / 10000;

        // Slippage is 0.5% by default
        let slippage = (amount + fee) * slippage_bps.unwrap_or(50) / 10000;

        Ok(amount + fee + slippage)
    }

    // pub async buy_and_bridge(&self, amount: U256, slippage_bps: Option<u32>) -> Result<U256> {
    //     let amount = self.get_gross_buy_amount(amount, slippage_bps).await?;
    //     let tx = self.contract.buy_and_bridge(amount).from(self.wallet.clone());
    //     let tx = tx.gas_price(0u32.into());
    //     let tx = tx.gas_limit(1_000_000u32.into());
    //     let tx = tx.send().await?;
    //     let receipt = tx.await?;
    //     Ok(receipt.gas_used.unwrap())
    // }
}