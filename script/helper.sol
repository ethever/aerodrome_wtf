import "@openzeppelin/contracts/interfaces/IERC20.sol";

contract Helper {
    address owner;
    address pool;
    // weth
    address token0 = address(0x4200000000000000000000000000000000000006);
    // cbLTC
    address token1 = address(0xcb17C9Db87B595717C857a08468793f5bAb6445F);

    constructor(address _pool) {
        owner = msg.sender;
        pool = _pool;
    }

    function withdrawAll() public {
        IERC20(token0).transfer(
            address(owner),
            IERC20(token0).balanceOf(address(this))
        );

        IERC20(token1).transfer(
            address(owner),
            IERC20(token1).balanceOf(address(this))
        );

        payable(owner).call{value: address(this).balance}("");
    }

    function mint(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    ) external returns (uint256 amount0, uint256 amount1) {
        require(msg.sender == owner, "msg.sender == owner");
        (amount0, amount1) = CLPool(pool).mint(
            address(this),
            tickLower,
            tickUpper,
            amount,
            data
        );
    }

    function uniswapV3MintCallback(
        uint256 a0,
        uint256 a1,
        bytes calldata data
    ) external {
        require(msg.sender == pool, "msg.sender == pool");

        IERC20(token0).transfer(msg.sender, a0);
        IERC20(token1).transfer(msg.sender, a1);
    }

    function burn(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    ) external returns (uint256 amount0, uint256 amount1) {
        require(msg.sender == owner, "msg.sender == owner");
        (amount0, amount1) = CLPool(pool).burn(tickLower, tickUpper, amount);
    }

    function collect(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0Requested,
        uint128 amount1Requested
    ) external returns (uint128 amount0, uint128 amount1) {
        require(msg.sender == owner, "msg.sender == owner");
        (amount0, amount1) = CLPool(pool).collect(
            address(this),
            tickLower,
            tickUpper,
            amount0Requested,
            amount1Requested
        );
    }

    function balances() public view returns (uint256, uint256) {
        return (
            IERC20(token0).balanceOf(address(this)),
            IERC20(token1).balanceOf(address(this))
        );
    }
}

interface CLPool {
    function mint(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    ) external returns (uint256 amount0, uint256 amount1);
    function burn(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    ) external returns (uint256 amount0, uint256 amount1);

    function collect(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0Requested,
        uint128 amount1Requested
    ) external returns (uint128 amount0, uint128 amount1);
}
