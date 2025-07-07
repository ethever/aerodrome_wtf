# First, fork with submodules:

``` bash
git clone --recurse-submodules https://github.com/ethever/aerodrome_wtf.git
```

# Second

build the solidity,

```
forge build
```

# Third

Fork `base` chain locally using Anvil:

``` bash
anvil --rpc-url https://base-mainnet.g.alchemy.com/v2/CH4meQjhQaPZ2GGAnVieDIVOPPNvgdLD
```

# Fourth

```
cargo run
```

