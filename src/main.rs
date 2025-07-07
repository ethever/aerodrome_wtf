use crate::ISwapRouter::ExactInputSingleParams;
use alloy::{
    primitives::{Address, FixedBytes, Signed, U256, Uint, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};

use eyre::Result;
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    CLPool,
    concat!(env!("CARGO_MANIFEST_DIR"), "/abis/clpool.json")
);

sol!(
    #[sol(rpc)]
    WETH,
    concat!(env!("CARGO_MANIFEST_DIR"), "/abis/weth.json")
);

sol!(
    #[sol(rpc)]
    RouterV3,
    concat!(env!("CARGO_MANIFEST_DIR"), "/abis/pancakerouterv3.json")
);

sol!(
    #[sol(rpc)]
    Helper,
    // you need to run `forge build` first to generate the ABI files
    concat!(env!("CARGO_MANIFEST_DIR"), "/out/helper.sol/Helper.json")
);

sol!(
    #[sol(rpc)]
    IERC20,
    // you need to run `forge build` first to generate the ABI files
    concat!(env!("CARGO_MANIFEST_DIR"), "/out/IERC20.sol/IERC20.json")
);

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv()?;

    let pk: PrivateKeySigner = env::var("PRIVATE_KEY")
        .expect("PRIVATE_KEY env unset!")
        .parse()?;

    let this = pk.address();
    assert_eq!(
        pk.address(),
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".parse::<Address>()?
    );

    let provider = ProviderBuilder::new()
        .wallet(pk.clone())
        .connect("http://localhost:8545")
        .await?;

    // https://basescan.org/address/0x200681425b0C8D78C6a467512C5D49FA56BaC88A
    let pool = CLPool::new(
        "0x200681425b0C8D78C6a467512C5D49FA56BaC88A".parse()?,
        provider.clone(),
    );

    // https://basescan.org/address/0x4200000000000000000000000000000000000006
    let weth = WETH::new(
        "0x4200000000000000000000000000000000000006".parse()?,
        provider.clone(),
    );

    // https://basescan.org/address/0x1b81D678ffb9C0263b24A97847620C99d213eB14
    let router = RouterV3::new(
        "0x1b81D678ffb9C0263b24A97847620C99d213eB14".parse()?,
        provider.clone(),
    );

    let cb_ltc = IERC20::new(
        "0xcb17C9Db87B595717C857a08468793f5bAb6445F".parse()?,
        provider.clone(),
    );

    let balance = provider.get_balance(pk.address()).await?;

    let tx_hash = weth
        .deposit()
        .value(balance - U256::from(1_000_000_000_000_000_000u64))
        .send()
        .await
        .map_err(|e| eyre::eyre!("Failed to deposit WETH: {}", e))?
        .watch()
        .await?;

    println!("Deposit WETH transaction: {:?}", tx_hash);

    weth.approve(router.address().clone(), U256::MAX)
        .send()
        .await
        .map_err(|e| eyre::eyre!("Failed to approve WETH: {}", e))?
        .watch()
        .await?;

    // swap for some cbLTC
    let swap_cbltc_tx_hash = router
        .exactInputSingle(ExactInputSingleParams {
            tokenIn: weth.address().clone(),
            tokenOut: cb_ltc.address().clone(),
            fee: Uint::from(500),
            recipient: this,
            deadline: U256::from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 1000),
            amountIn: weth.balanceOf(this).call().await?.div_ceil(U256::from(2)),
            // unsafe!!
            amountOutMinimum: U256::ZERO,
            sqrtPriceLimitX96: Uint::<160, 3>::ZERO,
        })
        .send()
        .await
        .map_err(|e| eyre::eyre!("Failed to swap for cbLTC: {}", e))?
        .watch()
        .await?;

    println!("Swap for cbLTC transaction: {:?}", swap_cbltc_tx_hash);

    let helper = Helper::deploy(provider.clone(), pool.address().clone())
        .await
        .map_err(|e| eyre::eyre!("Deploy helper contract failed: {}", e))?;

    let tx_hash = weth
        .transfer(helper.address().clone(), weth.balanceOf(this).call().await?)
        .send()
        .await
        .map_err(|e| eyre::eyre!("Send weth to helper contract failed: {}", e))?
        .watch()
        .await?;
    println!("Transfer WETH to helper contract: {:?}", tx_hash);

    let tx_hash = cb_ltc
        .transfer(
            helper.address().clone(),
            cb_ltc.balanceOf(this).call().await?,
        )
        .send()
        .await
        .map_err(|e| eyre::eyre!("Send cbLTC to helper contract failed: {}", e))?
        .watch()
        .await?;
    println!("Transfer cbLTC to helper contract: {:?}", tx_hash);

    let tick_spacing = pool.tickSpacing().call().await?;
    println!("Tick Spacing: {:?}", tick_spacing);

    loop {
        let current_tick = pool.slot0().call().await?.tick;
        let tick_aligned = current_tick - current_tick.rem_euclid(tick_spacing);
        println!("Current Tick: {:?}", current_tick);

        println!("Current Tick Aligned: {:?}", tick_aligned);

        let tick_lower = tick_aligned - tick_spacing;
        let tick_upper = tick_aligned + tick_spacing;
        let tx = helper
            .mint(tick_lower, tick_upper, 10, Default::default())
            .send()
            .await?
            .watch()
            .await?;

        println!(
            "Mint transaction: {:?} with tick [{},{}]",
            tx, tick_lower, tick_upper,
        );

        let position_info = pool
            .positions(index(helper.address().clone(), tick_lower, tick_upper))
            .call()
            .await?;

        println!("Position info: {:#?}", position_info);

        println!("----------------Waiting for next tick...(10sec)-----------------");
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

fn index(owner: Address, tick_lower: Signed<24, 1>, tick_upper: Signed<24, 1>) -> FixedBytes<32> {
    use ethers_core::{
        abi::{Int, Token, encode_packed},
        types::H160,
    };

    let bytes = encode_packed(&vec![
        Token::Address(H160::from_slice(owner.as_slice())),
        Token::Int(Int::from_big_endian(
            tick_lower.to_be_bytes::<3>().as_slice(),
        )),
        Token::Int(Int::from_big_endian(
            tick_upper.to_be_bytes::<3>().as_slice(),
        )),
    ])
    .unwrap();
    keccak256(bytes.as_slice())
}

#[test]
fn index_should_work() {
    index(
        Address::default(),
        Signed::<24, 1>::ZERO,
        Signed::<24, 1>::ZERO,
    );
}
