use crate::{
    CLPool::slot0Return, Helper::HelperErrors, ISwapRouter::ExactInputSingleParams,
    maths::get_liquidity_for_amounts,
};
use alloy::{
    primitives::{Address, FixedBytes, Signed, U256, Uint, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::Result;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_rational::BigRational;
use num_traits::ToPrimitive;
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};
use uniswap_v3_math::tick_math::get_sqrt_ratio_at_tick;

mod maths;

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
    #[sol(rpc, all_derives)]
    #[derive(Debug, Default)]
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
        .connect(&env::var("RPC_URL")?)
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

    let balance = provider.get_balance(this).await?;

    let tx_hash = weth
        .deposit()
        .value(balance - U256::from(1_000_000_000_000_000_000u64))
        .send()
        .await
        .map_err(|e| eyre::eyre!("Failed to deposit WETH: {}", e))?
        .watch()
        .await?;

    println!("Deposit WETH transaction: {:?}", tx_hash);

    let token0_decimals = 18u8;
    let token1_decimals = 8u8;

    let tx_hash = weth
        .approve(router.address().clone(), U256::MAX)
        .send()
        .await
        .map_err(|e| eyre::eyre!("Failed to approve WETH: {}", e))?
        .watch()
        .await?;
    println!("Approved WETH to router contract: {:?}", tx_hash);

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
        let balances = helper.balances().call().await?;
        println!(
            "Helper contract balances: WETH: {}, cbLTC: {}",
            balances._0, balances._1
        );

        let slot0Return {
            tick: current_tick,
            sqrtPriceX96: sqrt_price_x96,
            ..
        } = pool.slot0().call().await?;

        let cb_ltc_per_weth = raw_price(sqrt_price_x96);

        println!(
            "Current tick: {}, {} cbLTC per WETH, {} WETH per cbLTC",
            current_tick,
            price(cb_ltc_per_weth.clone(), token0_decimals, token1_decimals)
                .to_f64()
                .unwrap(),
            price(cb_ltc_per_weth.clone(), token0_decimals, token1_decimals)
                .recip()
                .to_f64()
                .unwrap()
        );

        // cbLTC - WETH
        // cbLTC/weth >= cb_ltc_per_weth
        let (token1_to_add, token0_to_add) =
            if BigRational::new(balances._1.into(), balances._0.into()) >= cb_ltc_per_weth {
                (
                    BigRational::from_integer(balances._0.into()) * cb_ltc_per_weth,
                    BigRational::from(BigInt::from(balances._0)),
                )
            } else {
                (
                    BigRational::from(BigInt::from(balances._1)),
                    BigRational::from_integer(balances._1.into()) * cb_ltc_per_weth.recip(),
                )
            };

        let tick_aligned = current_tick - current_tick.rem_euclid(tick_spacing);

        println!("Current Tick Aligned: {:?}", tick_aligned);

        let tick_lower = tick_aligned - tick_spacing;
        let tick_upper = tick_aligned + tick_spacing;

        let max_liquidity: u128 = {
            let token0 = token0_to_add.to_integer();
            let token1 = token1_to_add.to_integer();

            let res = get_liquidity_for_amounts(
                U256::from(sqrt_price_x96),
                get_sqrt_ratio_at_tick(tick_lower.as_i32())?,
                get_sqrt_ratio_at_tick(tick_upper.as_i32())?,
                token0.clone().try_into().unwrap(),
                token1.clone().try_into().unwrap(),
            )
            .to_u128()
            .unwrap();
            println!(
                "tick_lower: {}, tick_upper: {}, sqrt_price_x96: {}, token0: {}, token1: {}, liquidity: {}",
                tick_lower, tick_upper, sqrt_price_x96, token0, token1, res
            );
            res
        };

        // Mint liquidity.
        {
            println!("Liquidity to mint: {}", max_liquidity);
            let tx = {
                let res = helper.mint(tick_lower, tick_upper, max_liquidity, Default::default());

                let res = res.send();
                let res = res.await.map_err(|e| {
                    if let Some(e) = e.as_decoded_interface_error::<HelperErrors>() {
                        eyre::eyre!("{:?}", e)
                    } else {
                        eyre::eyre!("Mint liquidity failed: {}", e)
                    }
                })?;
                let res = res.watch();
                let res = res.await?;
                res
            };

            println!(
                "Mint liquidity transaction: {:?} with tick [{},{}]",
                tx, tick_lower, tick_upper,
            );

            let position_info = pool
                .positions(index(helper.address().clone(), tick_lower, tick_upper))
                .call()
                .await?;
            println!("Position info: {:#?}", position_info);

            let balances = helper.balances().call().await?;
            println!(
                "Helper contract balances: WETH: {}, cbLTC: {}",
                balances._0, balances._1
            );

            println!("----------------Waiting for burning liquidity(5sec)-----------------");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            // Burn liquidity.
            {
                let tx = helper
                    .burn(tick_lower, tick_upper, position_info.liquidity)
                    .send()
                    .await?
                    .watch()
                    .await?;
                println!(
                    "Burn liquidity transaction: {:?} with tick [{},{}], liquidity: {}",
                    tx, tick_lower, tick_upper, position_info.liquidity
                );

                let position_info = pool
                    .positions(index(helper.address().clone(), tick_lower, tick_upper))
                    .call()
                    .await?;
                println!("Position info: {:#?}", position_info);
            }
        }

        // Collect tokens.
        {
            let tx = helper
                .collect(tick_lower, tick_upper, u128::MAX, u128::MAX)
                .send()
                .await?
                .watch()
                .await?;

            println!(
                "Collect fees transaction: {:?} with tick [{},{}]",
                tx, tick_lower, tick_upper
            );

            let balances = helper.balances().call().await?;
            println!(
                "Helper contract balances: WETH: {}, cbLTC: {}",
                balances._0, balances._1
            );
        }

        println!("----------------Waiting for tick(10sec)-----------------");
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

/// Token1 per token0 raw price
fn raw_price(sqrt_price_x96: Uint<160, 3>) -> num_rational::BigRational {
    let res: BigUint = sqrt_price_x96.into();
    let denom = BigUint::from(2u32).pow(96);
    let price = BigRational::new(res.to_bigint().unwrap(), denom.to_bigint().unwrap());
    let price = price.pow(2);
    price
}

fn price(
    raw_price: num_rational::BigRational,
    token0_decimals: u8,
    token1_decimals: u8,
) -> num_rational::BigRational {
    raw_price
        * num_rational::BigRational::from_integer(10.into())
            .pow((token0_decimals - token1_decimals).into())
}
#[test]
fn test_rounding() {
    let r = num_rational::BigRational::new(1.into(), 2.into());
    println!("{}", r);
    println!("{}", r.ceil());
    println!("{}", r.floor());
    println!("{}", r.to_integer());
}
#[test]
fn error_should_work() {
    let res = HelperErrors::TokenInsufficient(Default::default());
    println!("{:?}", res);
}
#[test]
fn findout_proper_token_amounts_should_work() {
    use alloy::uint;
    use num_rational::BigRational;
    use num_traits::FromPrimitive;

    struct Balances {
        _0: U256,
        _1: U256,
    }
    // mock balances in the helper contract.
    let balances = Balances {
        // weth token0
        _0: uint!(100U256),
        // cbLTC token1
        _1: uint!(200U256),
    };

    let cb_ltc_per_weth = BigRational::from_f64(4f64).unwrap();
    println!("cb_ltc_per_weth: {}", cb_ltc_per_weth);

    let res = {
        // cbLTC/weth >= cb_ltc_per_weth
        if BigRational::new(balances._1.into(), balances._0.into()) >= cb_ltc_per_weth {
            let res = BigRational::from_integer(balances._0.into()) * cb_ltc_per_weth;
            let res: U256 = res.to_integer().try_into().unwrap();
            (res, balances._0)
        } else {
            let res = BigRational::from_integer(balances._1.into()) * cb_ltc_per_weth.recip();
            let res: U256 = res.to_integer().try_into().unwrap();

            (balances._1, res)
        }
    };

    println!("{res:?}");
}

#[tokio::test]
#[ignore = "network required"]
async fn pool_cur_price() {
    use num_traits::ToPrimitive;
    let provider = ProviderBuilder::new()
        .connect("http://localhost:8545")
        .await
        .unwrap();

    // https://basescan.org/address/0x200681425b0C8D78C6a467512C5D49FA56BaC88A
    let pool = CLPool::new(
        "0x200681425b0C8D78C6a467512C5D49FA56BaC88A"
            .parse()
            .unwrap(),
        provider.clone(),
    );

    let slot0Return {
        sqrtPriceX96: sqrt_price_x96,
        ..
    } = pool.slot0().call().await.unwrap();
    println!("Current sqrtPriceX96: {}", sqrt_price_x96);

    let cb_ltc_per_weth = price(raw_price(sqrt_price_x96), 18, 8);
    println!("{} cbLTC per WETH", cb_ltc_per_weth.to_f64().unwrap());

    let weth_per_cb_ltc = cb_ltc_per_weth.recip();

    println!("{} WETH per cbLTC", weth_per_cb_ltc.to_f64().unwrap());
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
