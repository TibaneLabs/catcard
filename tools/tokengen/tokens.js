// Mantle. Addresses from CoinGecko's mantle asset platform, decimals read
  // on-chain. Same trap as elsewhere: AUSD is 6, FBTC/uniBTC are 8, but
  // solvBTC/xSolvBTC are 18. Tokenized equities (the …X stocks) are skipped --
  // real assets, but not what dev dust looks like.
  //
  // Mantle exposes an ERC20 predeploy that mirrors the native MNT balance; it
  // is excluded on purpose (see the note beside WMNT below).
  mantle: [
    E('USDT', '0x201EBa5CC46D216Ce6DC03F6a759e8E766e956aE', 6, 'tether', { stable: true }),
    E('USDC', '0x09Bc4E0D864854c6aFB6eB9A9cdF58aC190D0dF9', 6, 'mantle-bridged-usdc-mantle', { stable: true }),
    E('USDT0', '0x779Ded0c9e1022225f8E0630b35a9b54bE713736', 6, 'usdt0', { stable: true }),
    E('USDe', '0x5d3a1Ff2b6BAb83b63cd9AD0787074081a52ef34', 18, 'ethena-usde', { stable: true }),
    E('USD1', '0x111111d2bf19e43C34263401e0CAd979eD1cdb61', 18, 'usd1-wlfi', { stable: true }),
    E('AUSD', '0x00000000eFE302BEAA2b3e6e1b18d08D69a9012a', 6, 'agora-dollar', { stable: true }),
    E('USDA', '0x075df695b8E7f4361FA7F8c1426C63f11B06e326', 18, 'usda-2', { stable: true }),
    // Yield-bearing, so worth more than $1 -- no stable fallback, they must price.
    E('USDY', '0x5bE26527e817998A7206475496fDE1E68957c5A6', 18, 'ondo-us-dollar-yield'),
    E('sUSDe', '0x211Cc4DD073734dA055fbF44a2b4667d5E5fE5d2', 18, 'ethena-staked-usde'),
    E('WMNT', '0x78c1b0C915c4FAA5FffA6CAbf0219DA63d7f4cb8', 18, 'wrapped-mantle'),
    // Deliberately NOT listed: the MNT ERC20 predeploy at
    // 0xDeadDeAd…DeAd0000. Its balanceOf is an ERC20 *view* of the native MNT
    // balance, not a separate holding -- verified identical to eth_getBalance
    // on three addresses. Listing it would double-count MNT in the report and
    // plan an ERC20 transfer AND a native sweep of the very same funds.
    // WMNT above is a genuinely distinct token and stays.
    E('WETH', '0xdEAddEaDdeadDEadDEADDEAddEADDEAddead1111', 18, 'wrapped-ether-mantle-bridge'),
    E('mETH', '0xcDA86A272531e8640cD7F1a92c01839911B90bb0', 18, 'mantle-staked-ether'),
    E('cmETH', '0xE6829d9a7eE3040e1276Fa75293Bde931859e8fA', 18, 'mantle-restaked-eth'),
    E('rsETH', '0x4186BFC76E2E237523CBC30FD220FE055156b41F', 18, 'kelp-dao-restaked-eth'),
    E('FBTC', '0xC96dE26018A54D51c097160568752c4E3BD6C364', 8, 'ignition-fbtc'),
    E('solvBTC', '0xa68d25fC2AF7278db4BcdcAabce31814252642a9', 18, 'solv-btc'),
    E('xSolvBTC', '0x1d40baFC49c37CdA49F2a5427E2FB95E1e3FCf20', 18, 'solv-protocol-solvbtc-bbn'),
    E('uniBTC', '0x93919784C523f39CACaa98Ee0a9d96c3F32b593e', 8, 'universal-btc'),
    E('ENA', '0x58538e6A46E07434d7E7375Bc268D3cb839C0133', 18, 'ethena'),
    E('LINK', '0xfe36cF0B43aAe49fBc5cFC5c0AF22a623114E043', 18, 'chainlink'),
    E('WOO', '0xF3df0A31ec5EA438150987805e841F960b9471b6', 18, 'woo-network'),
  ],

  arbitrum: [
    E('USDC', '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', 6, 'usd-coin', { stable: true }),
    E('USDC.e', '0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8', 6, 'usd-coin', { stable: true }),
    E('USDT', '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9', 6, 'tether', { stable: true }),
    E('DAI', '0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1', 18, 'dai', { stable: true }),
    E('crvUSD', '0x498Bf2B1e120FeD3ad3D42EA2165E9b73f99C1e5', 18, 'crvusd', { stable: true }),
    E('WETH', '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1', 18, 'weth'),
    E('wstETH', '0x5979D7b546E38E414F7E9822514be443A4800529', 18, 'wrapped-steth'),
    E('weETH', '0x35751007a407ca6FEFfE80b3cB397736D2cf4dbe', 18, 'wrapped-eeth'),
    E('WBTC', '0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f', 8, 'wrapped-bitcoin'),
    E('ARB', '0x912CE59144191C1204E64559FE8253a0e49E6548', 18, 'arbitrum'),
    E('GMX', '0xfc5A1A6EB076a2C7aD06eD22C90d7E710E35ad0a', 18, 'gmx'),
    E('PENDLE', '0x0c880f6761F1af8d9Aa9C466984b80DAb9a8c9e8', 18, 'pendle'),
    E('LINK', '0xf97f4df75117a78c1A5a0DBb814Af92458539FB4', 18, 'chainlink'),
    E('UNI', '0xFa7F8980b0f1E64A2062791cc3b0871572f1F7f0', 18, 'uniswap'),
    E('MAGIC', '0x539bdE0d7Dbd336b79148AA742883198BBF60342', 18, 'magic'),
  ],

  optimism: [
    E('USDC', '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85', 6, 'usd-coin', { stable: true }),
    E('USDC.e', '0x7F5c764cBc14f9669B88837ca1490cCa17c31607', 6, 'usd-coin', { stable: true }),
    E('USDT', '0x94b008aA00579c1307B0EF2c499aD98a8ce58e58', 6, 'tether', { stable: true }),
    E('DAI', '0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1', 18, 'dai', { stable: true }),
    E('WETH', '0x4200000000000000000000000000000000000006', 18, 'weth'),
    E('wstETH', '0x1F32b1c2345538c0c6f582fCB022739c4A194Ebb', 18, 'wrapped-steth'),
    E('WBTC', '0x68f180fcCe6836688e9084f035309E29Bf0A2095', 8, 'wrapped-bitcoin'),
    E('OP', '0x4200000000000000000000000000000000000042', 18, 'optimism'),
    E('SNX', '0x8700dAec35aF8Ff88c16BdF0418774CB3D7599B4', 18, 'havven'),
    E('VELO', '0x9560e827aF36c94D2Ac33a39bCE1Fe78631088Db', 18, 'velodrome-finance'),
    E('LINK', '0x350a791Bfc2C21F9Ed5d10980Dad2e2638ffa7f6', 18, 'chainlink'),
  ],

  // HyperEVM. Addresses come from CoinGecko's hyperevm asset platform and the
  // decimals were read off-chain-of-record via multicall, not assumed -- the BTC
  // wrappers here disagree with each other (solvBTC is 18, UBTC/brBTC are 8) and
  // MOVE/WXRP/thBILL are not 18 either, so guessing would misprice by 1e10+.
  // Ondo-style tokenized equities are on this chain too but are left out: real,
  // but not what accumulates in a dev wallet.
  hyperevm: [
    E('USDC', '0xb88339CB7199b77E23DB6E890353E22632Ba630f', 6, 'usd-coin', { stable: true }),
    E('USDT0', '0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb', 6, 'usdt0', { stable: true }),
    E('USDe', '0x5d3a1Ff2b6BAb83b63cd9AD0787074081a52ef34', 18, 'ethena-usde', { stable: true }),
    E('feUSD', '0x02c6a2fA58cC01A18B8D9E00eA48d65E4dF26c70', 18, 'felix-feusd', { stable: true }),
    // Yield-bearing, so worth more than $1 -- no stable fallback, they must price.
    E('sUSDe', '0x211Cc4DD073734dA055fbF44a2b4667d5E5fE5d2', 18, 'ethena-staked-usde'),
    E('wsrUSD', '0x04716DB62C085D9e08050fcF6F7D775A03d07720', 18, 'wrapped-savings-rusd'),
    E('thBILL', '0xfDD22Ce6D1F66bc0Ec89b20BF16CcB6670F55A5a', 6, 'theo-short-duration-us-treasury-fund'),
    // HYPE and its liquid-staking derivatives.
    E('WHYPE', '0x5555555555555555555555555555555555555555', 18, 'wrapped-hype'),
    E('kHYPE', '0xfD739d4e423301CE9385c1fb8850539D657C296D', 18, 'kinetic-staked-hype'),
    E('stHYPE', '0xfFaa4a3D97fE9107Cef8a3F48c069F577Ff76cC1', 18, 'staked-hype'),
    E('vkHYPE', '0x9BA2EDc44E0A4632EB4723E81d4142353e1bB160', 18, 'kinetiq-earn-vault'),
    E('weETH', '0xA3D68b74bF0528fdD07263c60d6488749044914b', 18, 'wrapped-eeth'),
    E('UBTC', '0x9FDBdA0A5e284c32744D2f17Ee5c74B284993463', 8, 'unit-bitcoin'),
    E('uniBTC', '0xF9775085d726E782E83585033B58606f7731AB18', 8, 'universal-btc'),
    E('solvBTC', '0xaE4EFbc7736f963982aACb17EFA37fCBAb924cB3', 18, 'solv-btc'),
    E('xSolvBTC', '0xc99F5c922DAE05B6e2ff83463ce705eF7C91F077', 18, 'solv-protocol-solvbtc-bbn'),
    E('brBTC', '0xDfc7D2d003A053b2E0490531e9317A59962b511E', 8, 'bedrock-btc'),
    E('XAUT0', '0xf4D9235269a96aaDaFc9aDAe454a0618eBE37949', 6, 'tether-gold-tokens'),
    E('LINK', '0x1AC2EE68b8d038C982C1E1f73F596927dd70De59', 18, 'chainlink'),
    E('PENDLE', '0xD6Eb81136884713E843936843E286FD2a85A205A', 18, 'pendle'),
    E('APE', '0xab11329560Fa9C9c860Bb21A9342215a1265BBB0', 18, 'apecoin'),
    E('PENGU', '0xFa44C2634fF17CBE26dc3007D36BD61c79068c14', 18, 'pudgy-penguins'),
    E('WXRP', '0xB73eE5488647a6302EBf5FEE8Af3152F6960AE4c', 6, 'hex-trust-wrapped-xrp'),
    E('PURR', '0x9b498C3c8A0b8CD8BA1D9851d40D186F1872b44E', 18, 'purr-2'),
    E('MOVE', '0x3073f7aAA4DB83f95e9FFf17424F71D4751a3073', 8, 'movement'),
    E('REKT', '0xc12E26AB94D1e62F18373cF25e43AFA7B2AF1cDc', 18, 'rekt-4'),
  ],
  // Plasma is a stablecoin-first L1, so the list leans that way. Addresses were
  // taken from CoinGecko's plasma asset platform rather than written by hand,
  // then verified on-chain by scripts/check-tokens.js.
  plasma: [
    E('USDT0', '0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb', 6, 'usdt0', { stable: true }),
    E('USDe', '0x5d3a1Ff2b6BAb83b63cd9AD0787074081a52ef34', 18, 'ethena-usde', { stable: true }),
    E('GHO', '0xb77E872A68C62CfC0dFb02C067Ecc3DA23B4bbf3', 18, 'gho', { stable: true }),
    E('USDai', '0x0A1a1A107E45b7Ced86833863f482BC5f4ed82EF', 18, 'usdai', { stable: true }),
    E('syrupUSDT', '0xC4374775489CB9C56003BF2C9b12495fC64F0771', 6, 'syrupusdt', { stable: true }),
    // Yield-bearing, so worth more than $1 -- no stable fallback, they must price.
    E('sUSDe', '0x211Cc4DD073734dA055fbF44a2b4667d5E5fE5d2', 18, 'ethena-staked-usde'),
    E('sUSDai', '0x0B2b2B2076d95dda7817e785989fE353fe955ef9', 18, 'susdai'),
    E('xUSD', '0x6eAf19b2FC24552925dB245F9Ff613157a7dbb4C', 6, 'staked-stream-usd'),
    E('WXPL', '0x6100E367285b01F48D07953803A2d8dCA5D19873', 18, 'wrapped-xpl'),
    E('WETH', '0x9895D81bB462A195b4922ED7De0e3ACD007c32CB', 18, 'stargate-bridged-weth'),
    E('weETH', '0xA3D68b74bF0528fdD07263c60d6488749044914b', 18, 'wrapped-eeth'),
    E('rsETH', '0x9eCaf80c1303CCA8791aFBc0AD405c8a35e8d9f1', 18, 'kelp-dao-restaked-eth'),
    E('XAUT0', '0x1B64B9025EEbb9A6239575dF9Ea4b9Ac46D4d193', 6, 'tether-gold-tokens'),
    E('LINK', '0x76a443768A5e3B8d1AED0105FC250877841Deb40', 18, 'chainlink'),
    E('FLUID', '0x61E030A56D33e8260FdD81f03B162A79Fe3449Cd', 18, 'instadapp'),
    E('EUL', '0xca632FA58397391C750c13F935DAA61AbBe0BaA6', 18, 'euler'),
  ],

  polygon: [
    E('USDC', '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', 6, 'usd-coin', { stable: true }),
    E('USDC.e', '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', 6, 'usd-coin', { stable: true }),
    E('USDT', '0xc2132D05D31c914a87C6611C10748AEb04B58e8F', 6, 'tether', { stable: true }),
    E('DAI', '0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063', 18, 'dai', { stable: true }),
    E('WETH', '0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619', 18, 'weth'),
    E('WBTC', '0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6', 8, 'wrapped-bitcoin'),
    E('WPOL', '0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270', 18, 'polygon-ecosystem-token'),
    E('LINK', '0x53E0bca35eC356BD5ddDFebbD1Fc0fD03FaBad39', 18, 'chainlink'),
    E('AAVE', '0xD6DF932A45C0f255f85145f286eA0b292B21C90B', 18, 'aave'),
    E('QUICK', '0xB5C064F955D8e7F38fE0460C556a72987494eE17', 18, 'quickswap'),
  ],
}
