use crate::{
    chain::ChainConfigWithMeta,
    contracts::{self, exchange::BuyParams, permittable_token::PermittableToken},
    erc20::legacy_permit::Permit,
};
use chrono::Utc;
use ethers::{abi::*, prelude::k256::ecdsa::SigningKey, prelude::*};
use eyre::Result;

pub enum Coin {
    Dai = 0,
    Usdc = 1,
    Usdt = 2,
}

pub enum Lp {
    None = 0,
    DaiPsm = 1,
    CurveFi3pool = 2,
    UniswapV3 = 3,
}

pub enum ExchangeOptions {
    None = 0,
    Permit = 1,
    Bridge = 2,
    PermitAndBridge = 3,
}
// Define an Into trait for each of the above enums
// This will allow us to pass the enum values directly to the contract functions
// without having to convert them to u8 first
impl From<Coin> for u8 {
    fn from(val: Coin) -> Self {
        val as u8
    }
}

impl From<Lp> for u8 {
    fn from(val: Lp) -> Self {
        val as u8
    }
}

impl From<ExchangeOptions> for U256 {
    fn from(val: ExchangeOptions) -> Self {
        U256::from(val as u8)
    }
}

pub struct Exchange<M>
where
    M: Middleware + 'static,
{
    contract: contracts::exchange::Exchange<M>,
    curve: contracts::curve::Curve<M>,
    chain: ChainConfigWithMeta<M>,
    wallet: Wallet<SigningKey>,
    // The fee is in basis points (1/100th of a percent)
    fee_bps: u32,
}

impl<M> Exchange<M>
where
    M: Middleware + 'static,
{
    pub async fn new(
        chain: ChainConfigWithMeta<M>,
        wallet: Wallet<SigningKey>,
    ) -> Result<Exchange<M>> {
        let contract = contracts::exchange::Exchange::new(
            chain.get_address("OPENBZZ_EXCHANGE")?,
            chain.client(),
        );
        let curve =
            contracts::curve::Curve::new(chain.get_address("BONDING_CURVE")?, chain.client());
        let fee_bps = contract.fee().call().await?;
        Ok(Self {
            contract,
            curve,
            chain,
            wallet,
            fee_bps: fee_bps.as_u32(),
        })
    }

    pub async fn quote_gross_buy_amount(
        &self,
        amount: U256,
        slippage_bps: Option<u32>,
    ) -> Result<U256> {
        let dai_amount = self.curve.buy_price(amount).call().await?;

        Ok(self.get_gross_buy_amount(dai_amount, slippage_bps))
    }

    /// Given a required amount of BZZ, determine the amount of DAI that needs to be sent to the exchange
    /// contract to receive the required amount of BZZ.
    /// This is done by calling the `curve` contract's `getBuyAmount` function.
    /// The amount returned includes the fee and any slippage.
    pub fn get_gross_buy_amount(&self, amount: U256, slippage_bps: Option<u32>) -> U256 {
        // Add the fee and slippage
        let fee = amount * self.fee_bps / 10000;

        // Slippage is 0.5% by default
        let slippage = (amount + fee) * slippage_bps.unwrap_or(50) / 10000;

        amount + fee + slippage
    }

    /// Buy and bridge the given amount of BZZ to the given recipient.
    pub async fn buy_and_bridge_bzz(
        &self,
        amount: U256,
        slippage_bps: Option<u32>,
        receipient: Option<H160>,
    ) -> Result<TransactionReceipt> {
        let dai = PermittableToken::new(
            self.chain.get_address("DAI_ADDRESS_MAINNET").unwrap(),
            self.chain.client(),
        );

        // 1. Use a multicall to fetch the DAI value required, the exchange allowance, and the wallet's DAI balance
        let mut multicall = Multicall::new(self.chain.client(), None).await.unwrap();
        multicall.add_call(self.curve.buy_price(amount), false);
        multicall.add_call(
            dai.allowance(self.wallet.address(), self.contract.address()),
            false,
        );
        multicall.add_call(dai.balance_of(self.wallet.address()), false);

        let (dai_amount, allowance, balance): (U256, U256, U256) = multicall.call().await.unwrap();

        // 1. First determine the amount of DAI that needs to have a permit done for it
        let dai_amount = self.get_gross_buy_amount(dai_amount, slippage_bps);

        // 2. If the `balance` is less than `dai_amount`, there are not enough funds to buy the BZZ.
        //    Instruct the user on how much DAI needs to be in the wallet.
        if balance < dai_amount {
            return Err(eyre::eyre!(
                "Not enough DAI in wallet 0x{}. Need at least {} DAI",
                hex::encode(self.wallet.address()),
                ethers::utils::format_units(dai_amount, 18)?
            ));
        }

        // 3. If the `allowance` is less than `dai_amount`, then we need to do a PermitAndBridge
        //    Otherwise, we can just do a Bridge

        // The `data` field is used to pass the gnosis chain receipient address
        // to the `buy` function on the `Exchange` contract.
        let receipient = receipient.unwrap_or(self.wallet.address());
        let bridge_data = abi::encode(&[Token::Address(receipient)]);

        let (options, data) = if allowance < dai_amount {
            let permit = Permit::new(
                self.wallet.address(),
                self.contract.address(),
                None,
                (Utc::now().timestamp() as u32 + 60 * 30).into(),
                true,
                self.chain.client(),
                dai.address(),
            )
            .await?;

            let signature = permit
                .sign(
                    self.wallet.clone(),
                    self.chain.client(),
                    dai.address(),
                    None,
                )
                .await?;

            let permit_data = ethers::abi::encode(&[
                Token::Uint(permit.nonce),
                Token::Uint(permit.expiry),
                Token::Uint((signature.v as u8).into()),
                Token::Uint(signature.r),
                Token::Uint(signature.s),
            ]);
            (
                ExchangeOptions::PermitAndBridge,
                abi::encode(&[Token::Bytes(permit_data), Token::Bytes(bridge_data)]),
            )
        } else {
            (ExchangeOptions::Bridge, bridge_data)
        };

        // 4. Create the `BuyParams` struct
        let params = BuyParams {
            bzz_amount: amount,
            max_stablecoin_amount: dai_amount,
            input_coin: Coin::Dai.into(),
            lp: Lp::None.into(), // We only support using DAI for now
            options: options.into(),
            data: data.into(),
        };

        // Setup the signer with the given wallet
        let signer = SignerMiddleware::new(
            self.chain.client(),
            self.wallet.clone().with_chain_id(self.chain.chain_id()),
        );

        let contract =
            contracts::exchange::Exchange::new(self.contract.address(), signer.clone().into());

        // Use the handler to create a transaction request
        let description = format!(
            "Buying {} BZZ and sending to 0x{} on Gnosis Chain",
            ethers::utils::format_units(amount, 16)?,
            hex::encode(receipient)
        );

        let handler = crate::wallet::CliTransactionHandler::new(
            self.wallet.clone(),
            contract.buy(params),
            description,
        );

        // Send the transaction
        handler.handle(&self.chain, 1).await
    }
}
