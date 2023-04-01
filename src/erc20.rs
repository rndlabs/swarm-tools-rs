use ethers::prelude::*;

abigen!(
    ERC20,
    r#"[
        function DOMAIN_SEPARATOR() external view returns (bytes32)
        function name() external view returns (string)
        function nonces(address owner) external view returns (uint256)
        function permit(address _holder, address _spender, uint256 _nonce, uint256 _expiry, bool _allowed, uint8 _v, bytes32 _r, bytes32 _s) external
        function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external
    ]"#,
);

mod tests {
    use std::{path::PathBuf, sync::Arc};

    use super::*;
    use ethers::utils::{Anvil, AnvilInstance};

    pub async fn contract_fixture() -> (
        AnvilInstance,
        Address,
        Arc<Provider<Http>>,
        LocalWallet,
        H160,
        ERC20<Provider<Http>>,
    ) {
        // launch the network & connect to it
        let anvil = Anvil::new().spawn();
        let from = anvil.addresses()[0];
        let provider = Provider::try_from(anvil.endpoint())
            .unwrap()
            .with_sender(from)
            .interval(std::time::Duration::from_millis(10));
        let client = Arc::new(provider);
        let wallet: LocalWallet = anvil.keys()[0].clone().into();

        let contract = "ERC20";
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts/ERC20.sol");
        let compiled = Solc::default().compile_source(path.clone()).unwrap();
        let compiled = compiled.get(path.to_str().unwrap(), contract).unwrap();
        let factory = ContractFactory::new(
            compiled.abi.unwrap().clone(),
            compiled.bytecode().unwrap().clone(),
            client.clone(),
        );
        // let addr = factory.deploy
        let addr = factory
            .deploy(("TestERC20".to_string(), "TEST".to_string(), 18 as u8))
            .unwrap()
            .legacy()
            .send()
            .await
            .unwrap()
            .address();
        let contract = ERC20::new(addr, client.clone());

        (anvil, from, client, wallet, addr, contract)
    }
}

pub mod permit {
    use ethers::{
        prelude::k256::ecdsa::SigningKey,
        prelude::*,
        types::transaction::eip712::{EIP712Domain, EIP712WithDomain, Eip712},
    };
    use eyre::Result;
    use std::sync::Arc;

    use super::ERC20;

    #[derive(Eip712, EthAbiType, Clone)]
    #[eip712()]
    pub struct Permit {
        pub owner: Address,
        pub spender: Address,
        pub value: U256,
        pub nonce: U256,
        pub deadline: U256,
    }

    impl Permit {
        pub async fn new<M>(
            owner: Address,
            spender: Address,
            value: U256,
            nonce_offset: Option<U256>,
            deadline: U256,
            client: Arc<M>,
            token_address: H160,
        ) -> Result<Self>
        where
            M: Middleware,
        {
            client.clone().get_chainid().await.unwrap();
            let contract = ERC20::new(token_address, client.clone());

            Ok(Self {
                owner,
                spender,
                value,
                nonce: contract.nonces(owner).call().await.unwrap()
                    + nonce_offset.unwrap_or(U256::zero()),
                deadline,
            })
        }

        pub async fn sign<M>(
            &self,
            wallet: Wallet<SigningKey>,
            client: Arc<M>,
            token_address: H160,
            domain: Option<EIP712Domain>,
        ) -> Result<Signature>
        where
            M: Middleware,
        {
            // If the domain is not provided, run a closure to get the domain
            let domain = match domain {
                Some(domain) => domain,
                None => {
                    let contract = ERC20::new(token_address, client.clone());
                    let name = contract.name().call().await.unwrap();
                    let chain_id = client.get_chainid().await.unwrap();

                    EIP712Domain {
                        name: Some(name),
                        version: Some("1".to_string()),
                        chain_id: Some(chain_id),
                        verifying_contract: Some(token_address),
                        salt: None,
                    }
                }
            };

            let permit_message = EIP712WithDomain::new(self.clone())?.set_domain(domain);
            Ok(wallet.sign_typed_data(&permit_message).await?)
        }

        pub async fn permit_calldata<M>(
            &self,
            signature: Signature,
            client: Arc<M>,
            token_address: Address,
        ) -> Result<Bytes>
        where
            M: Middleware,
        {
            let contract = ERC20::new(token_address, client.clone());
            Ok(contract
                .permit(
                    self.owner,
                    self.spender,
                    self.value,
                    self.deadline,
                    signature.v.try_into().unwrap(),
                    signature.r.into(),
                    signature.s.into(),
                )
                .calldata()
                .unwrap())
        }
    }

    mod tests {
        use super::*;

        #[tokio::test]
        async fn generate_valid_permit() {
            let (_anvil, from, client, wallet, addr, contract) =
                super::super::tests::contract_fixture().await;

            let permit = Permit::new(
                from,
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                    .parse()
                    .unwrap(),
                U256::MAX,
                None,
                U256::MAX,
                client.clone(),
                addr,
            )
            .await
            .unwrap();

            let domain = EIP712Domain {
                name: Some("TestERC20".to_string()),
                version: Some("1".to_string()),
                chain_id: Some(31337.into()),
                verifying_contract: Some(addr),
                salt: None,
            };

            // Make sure that the domain separator is correct
            let domain_separator = contract.domain_separator().call().await.unwrap();
            assert_eq!(domain_separator, domain.separator());

            // // create a typed message
            let signature = permit
                .sign(wallet, client.clone(), addr, None)
                .await
                .unwrap();

            let res = contract
                .permit(
                    permit.owner,
                    permit.spender,
                    permit.value,
                    permit.deadline,
                    signature.v.try_into().unwrap(),
                    signature.r.into(),
                    signature.s.into(),
                )
                .call()
                .await;

            if res.is_err() {
                println!("{:?}", res);
            }

            // assert the call
            assert!(res.is_ok());
        }
    }
}

pub mod legacy_permit {
    use ethers::{
        prelude::k256::ecdsa::SigningKey,
        prelude::*,
        types::transaction::eip712::{EIP712Domain, EIP712WithDomain, Eip712},
    };
    use eyre::Result;
    use std::sync::Arc;

    use super::ERC20;

    #[derive(Eip712, EthAbiType, Clone)]
    #[eip712()]
    pub struct Permit {
        pub holder: Address,
        pub spender: Address,
        pub nonce: U256,
        pub expiry: U256,
        pub allowed: bool,
    }

    impl Permit {
        pub async fn new<M>(
            holder: Address,
            spender: Address,
            nonce_offset: Option<U256>,
            expiry: U256,
            allowed: bool,
            client: Arc<M>,
            token_address: H160,
        ) -> Result<Self>
        where
            M: Middleware,
        {
            client.clone().get_chainid().await.unwrap();
            let contract = ERC20::new(token_address, client.clone());

            Ok(Self {
                holder,
                spender,
                nonce: contract.nonces(holder).call().await.unwrap()
                    + nonce_offset.unwrap_or(U256::zero()),
                expiry,
                allowed,
            })
        }

        pub async fn sign<M>(
            &self,
            wallet: Wallet<SigningKey>,
            client: Arc<M>,
            token_address: Address,
            domain: Option<EIP712Domain>,
        ) -> Result<Signature>
        where
            M: Middleware,
        {
            // If the domain is not provided, run a closure to get the domain
            let domain = match domain {
                Some(domain) => domain,
                None => {
                    let contract = ERC20::new(token_address, client.clone());
                    let name = contract.name().call().await.unwrap();
                    let chain_id = client.get_chainid().await.unwrap();

                    EIP712Domain {
                        name: Some(name),
                        version: Some("1".to_string()),
                        chain_id: Some(chain_id),
                        verifying_contract: Some(token_address),
                        salt: None,
                    }
                }
            };

            let permit_message = EIP712WithDomain::new(self.clone())?.set_domain(domain);
            Ok(wallet.sign_typed_data(&permit_message).await?)
        }

        pub async fn permit_calldata<M>(
            &self,
            signature: Signature,
            client: Arc<M>,
            token_address: Address,
        ) -> Result<Bytes>
        where
            M: Middleware,
        {
            let contract = ERC20::new(token_address, client.clone());
            Ok(contract
                .permit_with_holder_and_spender_and_nonce_and_expiry_and_allowed_and_v_and_r(
                    self.holder,
                    self.spender,
                    self.nonce,
                    self.expiry,
                    self.allowed,
                    signature.v.try_into().unwrap(),
                    signature.r.into(),
                    signature.s.into(),
                )
                .calldata()
                .unwrap())
        }
    }

    pub mod tests {
        use super::*;

        #[tokio::test]
        async fn generate_valid_permit() {
            let (_anvil, from, client, wallet, addr, contract) =
                super::super::tests::contract_fixture().await;

            // create a permit
            let permit = Permit::new(
                from,
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                    .parse()
                    .unwrap(),
                None,
                U256::MAX,
                true,
                client.clone(),
                addr,
            )
            .await
            .unwrap();

            let domain = EIP712Domain {
                name: Some("TestERC20".to_string()),
                version: Some("1".to_string()),
                chain_id: Some(31337.into()),
                verifying_contract: Some(addr),
                salt: None,
            };

            // Make sure that the domain separator is correct
            let domain_separator = contract.domain_separator().call().await.unwrap();
            assert_eq!(domain_separator, domain.separator());

            // // create a typed message
            let signature = permit
                .sign(wallet, client.clone(), addr, None)
                .await
                .unwrap();

            let res = contract
                .permit_with_holder_and_spender_and_nonce_and_expiry_and_allowed_and_v_and_r(
                    permit.holder,
                    permit.spender,
                    permit.nonce,
                    permit.expiry,
                    permit.allowed,
                    signature.v.try_into().unwrap(),
                    signature.r.into(),
                    signature.s.into(),
                )
                .call()
                .await;

            if res.is_err() {
                println!("{:?}", res);
            }

            // assert the call
            assert!(res.is_ok());
        }
    }
}
