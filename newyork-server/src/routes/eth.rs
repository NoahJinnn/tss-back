use anyhow::Result;
use rocket::serde::json::Json;
use rocket::State;
use web3::types::{AccessList, Address, Bytes, TransactionParameters, H256, U256, U64};
use web3::{transports, Web3};

use crate::utils::requests::validate_auth_token;
use crate::AnyhowError;

use super::super::auth::guards::AuthPayload;
use super::super::AppConfig;

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct EthTxParamsResp {
    pub to: Option<Address>,
    pub nonce: U256,
    pub gas: U256,
    pub gas_price: U256,
    pub value: U256,
    pub data: Vec<u8>,
    pub transaction_type: Option<U64>,
    pub access_list: AccessList,
    pub max_priority_fee_per_gas: U256,
    pub chain_id: u64,
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct EthTxParamsReqBody {
    pub from_address: Address,
    pub to_address: Address,
    pub eth_value: f64,
}

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct EthSendTxResp {
    pub tx_hash: H256,
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct EthSendTxReqBody {
    pub raw_tx: Bytes,
}

const EIP1559_TX_ID: u64 = 2;

#[post("/eth/tx/params", format = "json", data = "<tx_info>")]
pub async fn tx_parameters(
    state: &State<AppConfig>,
    auth_payload: AuthPayload,
    tx_info: Json<EthTxParamsReqBody>,
) -> Result<Json<EthTxParamsResp>, AnyhowError> {
    validate_auth_token(state, &auth_payload).await?;
    let tx_params = create_eth_transaction(tx_info.to_address, tx_info.eth_value)?;
    let web3 = establish_web3_connection(&state.alchemy_api).await?;

    let (nonce, gas_price, chain_id) =
        get_chain_required_params(tx_info.from_address, tx_params.clone(), web3).await?;

    let max_priority_fee_per_gas = match tx_params.transaction_type {
        Some(tx_type) if tx_type == U64::from(EIP1559_TX_ID) => {
            tx_params.max_priority_fee_per_gas.unwrap_or(gas_price)
        }
        _ => gas_price,
    };

    let resp = EthTxParamsResp {
        to: tx_params.to,
        nonce,
        gas: tx_params.gas,
        gas_price,
        value: tx_params.value,
        data: tx_params.data.0,
        transaction_type: tx_params.transaction_type,
        access_list: tx_params.access_list.unwrap_or_default(),
        max_priority_fee_per_gas,
        chain_id,
    };

    Ok(Json(resp))
}

#[post("/eth/tx/send", format = "json", data = "<signed>")]
pub async fn tx_send(
    state: &State<AppConfig>,
    auth_payload: AuthPayload,
    signed: Json<EthSendTxReqBody>,
) -> Result<Json<EthSendTxResp>, AnyhowError> {
    validate_auth_token(state, &auth_payload).await?;
    let web3 = establish_web3_connection(&state.alchemy_api).await?;
    let tx_hash = send_tx(web3, signed.raw_tx.clone()).await?;

    Ok(Json(EthSendTxResp { tx_hash }))
}

fn create_eth_transaction(to: Address, eth_value: f64) -> Result<TransactionParameters> {
    Ok(TransactionParameters {
        to: Some(to),
        value: eth_to_wei(eth_value),
        ..Default::default()
    })
}

pub async fn establish_web3_connection(url: &str) -> Result<Web3<transports::WebSocket>> {
    let transport = transports::WebSocket::new(url).await?;
    Ok(Web3::new(transport))
}

pub async fn get_chain_required_params(
    from_address: Address,
    tx_params: TransactionParameters,
    web3: Web3<transports::WebSocket>,
) -> Result<(U256, U256, u64)> {
    macro_rules! maybe {
        ($o: expr, $f: expr) => {
            async {
                match $o {
                    Some(value) => Ok(value),
                    None => $f.await,
                }
            }
        };
    }

    let gas_price = match tx_params.transaction_type {
        Some(tx_type)
            if tx_type == U64::from(EIP1559_TX_ID) && tx_params.max_fee_per_gas.is_some() =>
        {
            tx_params.max_fee_per_gas
        }
        _ => tx_params.gas_price,
    };

    let (nonce, gas_price, chain_id) = futures::future::try_join3(
        maybe!(
            tx_params.nonce,
            web3.eth().transaction_count(from_address, None)
        ),
        maybe!(gas_price, web3.eth().gas_price()),
        maybe!(tx_params.chain_id.map(U256::from), web3.eth().chain_id()),
    )
    .await?;

    Ok((nonce, gas_price, chain_id.as_u64()))
}

pub async fn send_tx(web3: Web3<transports::WebSocket>, raw_tx: Bytes) -> Result<H256> {
    let tx_hash = web3.eth().send_raw_transaction(raw_tx).await?;
    Ok(tx_hash)
}

pub fn eth_to_wei(eth_value: f64) -> U256 {
    let result = eth_value * 1_000_000_000_000_000_000.0;
    let result = result as u128;

    U256::from(result)
}
