use alloy::primitives::U256;

/// Computes liquidity from amount0 and amount1 using Uniswap V3 math.
pub fn get_liquidity_for_amounts(
    sqrt_price_x96: U256,
    sqrt_price_a_x96: U256,
    sqrt_price_b_x96: U256,
    amount0: U256,
    amount1: U256,
) -> U256 {
    let (sqrt_price_a, sqrt_price_b) = if sqrt_price_a_x96 < sqrt_price_b_x96 {
        (sqrt_price_a_x96, sqrt_price_b_x96)
    } else {
        (sqrt_price_b_x96, sqrt_price_a_x96)
    };

    if sqrt_price_x96 <= sqrt_price_a {
        // price is below the range: only amount0 matters
        let numerator = amount0 * (sqrt_price_b - sqrt_price_a);
        let denom = sqrt_price_a * sqrt_price_b / U256::from(1u128 << 96);
        return numerator * U256::from(1u128 << 96) / denom;
    }

    if sqrt_price_x96 >= sqrt_price_b {
        // price is above the range: only amount1 matters
        return amount1 * U256::from(1u128 << 96) / (sqrt_price_b - sqrt_price_a);
    }

    // price is within the range: both tokens
    let liquidity0 = (amount0 * (sqrt_price_b - sqrt_price_x96)) * U256::from(1u128 << 96)
        / (sqrt_price_x96 * sqrt_price_b / U256::from(1u128 << 96));

    let liquidity1 = amount1 * U256::from(1u128 << 96) / (sqrt_price_x96 - sqrt_price_a);

    liquidity0.min(liquidity1)
}
