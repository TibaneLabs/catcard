//! Tokens this firmware can name, by chain and contract address.
//!
//! Generated. Edit the source list and re-run:
//!
//! ```text
//! tokens.js -> crates/catcard-evm/src/tokens.rs
//! ```
//!
//! **A row here is a claim about a contract**, and the screens treat it as one: the
//! address is shown whether or not it is named, and a name is a label on it rather
//! than a replacement for it. A table that mislabelled an address would let a hostile
//! contract borrow a familiar name at the moment somebody is deciding to sign, which
//! is why the generator refuses to invent either an address or a chain id.
//!
//! 181 tokens across 10 chains (1, 10, 56, 137, 999, 5000, 8453, 9745, 42161, 59144).

/// What a contract address turns out to be.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Token {
    /// The ticker, as the chain's own explorers write it.
    pub symbol: &'static str,
    /// Decimal places, for turning the raw amount into the number people use.
    pub decimals: u8,
}

use crate::literal::address;

/// `(chain_id, address, symbol, decimals)`, sorted so it can be searched.
#[rustfmt::skip]
static TOKENS: [(u64, [u8; 20], &str, u8); 181] = [
    (1, address("0x0d8775f648430679a709e98d2b0cb6250d2887ef"), "BAT", 18),
    (1, address("0x0f5d2fb29fb7d3cfee444a200298f468908cc942"), "MANA", 18),
    (1, address("0x111111111117dc0aa78b770fa6a738034120c302"), "1INCH", 18),
    (1, address("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"), "UNI", 18),
    (1, address("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"), "WBTC", 8),
    (1, address("0x3432b6a60d23ca0dfca7761b7ab56459d9c964d0"), "FXS", 18),
    (1, address("0x3845badade8e6dff049820680d1f14bd3903a5d0"), "SAND", 18),
    (1, address("0x40d16fc0246ad3160ccc09b8d0d3a2cd28ae6c2f"), "GHO", 18),
    (1, address("0x455e53cbb86018ac2b8092fdcd39d8444affc3f6"), "POL", 18),
    (1, address("0x4c9edd5852cd905f086c759e8383e09bff1e68b3"), "USDe", 18),
    (1, address("0x4d224452801aced8b2f0aebe155379bb5d594381"), "APE", 18),
    (1, address("0x514910771af9ca656af840dff83e8264ecf986ca"), "LINK", 18),
    (1, address("0x5a98fcbea516cf06857215779fd812ca3bef1b32"), "LDO", 18),
    (1, address("0x6982508145454ce325ddbe47a25d4ec3d2311933"), "PEPE", 18),
    (1, address("0x6b175474e89094c44da98b954eedeac495271d0f"), "DAI", 18),
    (1, address("0x6b3595068778dd592e39a122f4f5a5cf09c90fe2"), "SUSHI", 18),
    (1, address("0x6c3ea9036406852006290770bedfcaba0e23a0e8"), "PYUSD", 6),
    (1, address("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"), "wstETH", 18),
    (1, address("0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9"), "AAVE", 18),
    (1, address("0x853d955acef822db058eb8505911ed77f175b99e"), "FRAX", 18),
    (1, address("0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce"), "SHIB", 18),
    (1, address("0x9d39a5de30e57443bff2a8307a4256c8797a3497"), "sUSDe", 18),
    (1, address("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2"), "MKR", 18),
    (1, address("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), "USDC", 6),
    (1, address("0xa1290d69c65a6fe4df752f95823fae25cb99e5a7"), "rsETH", 18),
    (1, address("0xae78736cd615f374d3085123a210448e74fc6393"), "rETH", 18),
    (1, address("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"), "stETH", 18),
    (1, address("0xbe9895146f7af43049ca1c1ae358b0541ea49704"), "cbETH", 18),
    (1, address("0xbf5495efe5db9ce00f80364c8b423567e58d2110"), "ezETH", 18),
    (1, address("0xc00e94cb662c3520282e6f5717214004a7f26888"), "COMP", 18),
    (1, address("0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f"), "SNX", 18),
    (1, address("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"), "WETH", 18),
    (1, address("0xc18360217d8f7ab5e7c516566761ea12ce7f9d72"), "ENS", 18),
    (1, address("0xc944e90c64b2c07662a292be6244bdf05cda44a7"), "GRT", 18),
    (1, address("0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf"), "cbBTC", 8),
    (1, address("0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee"), "weETH", 18),
    (1, address("0xd33526068d116ce69f19a9ee46f0bd304f21a51f"), "RPL", 18),
    (1, address("0xd533a949740bb3306d119cc777fa900ba034cd52"), "CRV", 18),
    (1, address("0xdac17f958d2ee523a2206206994597c13d831ec7"), "USDT", 6),
    (1, address("0xf939e0a03fb07f59a73314e73794be0e57ac1b4e"), "crvUSD", 18),
    (10, address("0x0b2c639c533813f4aa9d7837caf62653d097ff85"), "USDC", 6),
    (10, address("0x1f32b1c2345538c0c6f582fcb022739c4a194ebb"), "wstETH", 18),
    (10, address("0x350a791bfc2c21f9ed5d10980dad2e2638ffa7f6"), "LINK", 18),
    (10, address("0x4200000000000000000000000000000000000006"), "WETH", 18),
    (10, address("0x4200000000000000000000000000000000000042"), "OP", 18),
    (10, address("0x68f180fcce6836688e9084f035309e29bf0a2095"), "WBTC", 8),
    (10, address("0x7f5c764cbc14f9669b88837ca1490cca17c31607"), "USDC.e", 6),
    (10, address("0x8700daec35af8ff88c16bdf0418774cb3d7599b4"), "SNX", 18),
    (10, address("0x94b008aa00579c1307b0ef2c499ad98a8ce58e58"), "USDT", 6),
    (10, address("0x9560e827af36c94d2ac33a39bce1fe78631088db"), "VELO", 18),
    (10, address("0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"), "DAI", 18),
    (56, address("0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"), "CAKE", 18),
    (56, address("0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3"), "DAI", 18),
    (56, address("0x1d2f0da169ceb9fc7b3144628db156f3f6c60dbe"), "XRP", 18),
    (56, address("0x2170ed0880ac9a755fd29b2688956bd959f933f8"), "ETH", 18),
    (56, address("0x3ee2200efb3400fabb9aacf31297cbdd1d435d47"), "ADA", 18),
    (56, address("0x4338665cbb7b2485a8855a139b75d5e34ab0db94"), "LTC", 18),
    (56, address("0x4b0f1812e5df2a09796481ff14017e6005508003"), "TWT", 18),
    (56, address("0x55d398326f99059ff775485246999027b3197955"), "USDT", 18),
    (56, address("0x7083609fce4d1d8dc0c979aab8c869ea2c873402"), "DOT", 18),
    (56, address("0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c"), "BTCB", 18),
    (56, address("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"), "USDC", 18),
    (56, address("0xba2ae424d960c26247dd6c32edc70b295c744c43"), "DOGE", 8),
    (56, address("0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"), "WBNB", 18),
    (56, address("0xbf5140a22578168fd562dccf235e5d43a02ce9b1"), "UNI", 18),
    (56, address("0xc5f0f7b66764f6ec8c8dff7ba683102295e16409"), "FDUSD", 18),
    (56, address("0xe9e7cea3dedca5984780bafc599bd69add087d56"), "BUSD", 18),
    (56, address("0xf8a0bf9cf54bb92f17374d9e9a321e6a111a51bd"), "LINK", 18),
    (137, address("0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"), "WPOL", 18),
    (137, address("0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6"), "WBTC", 8),
    (137, address("0x2791bca1f2de4661ed88a30c99a7a9449aa84174"), "USDC.e", 6),
    (137, address("0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"), "USDC", 6),
    (137, address("0x53e0bca35ec356bd5dddfebbd1fc0fd03fabad39"), "LINK", 18),
    (137, address("0x7ceb23fd6bc0add59e62ac25578270cff1b9f619"), "WETH", 18),
    (137, address("0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"), "DAI", 18),
    (137, address("0xb5c064f955d8e7f38fe0460c556a72987494ee17"), "QUICK", 18),
    (137, address("0xc2132d05d31c914a87c6611c10748aeb04b58e8f"), "USDT", 6),
    (137, address("0xd6df932a45c0f255f85145f286ea0b292b21c90b"), "AAVE", 18),
    (999, address("0x02c6a2fa58cc01a18b8d9e00ea48d65e4df26c70"), "feUSD", 18),
    (999, address("0x04716db62c085d9e08050fcf6f7d775a03d07720"), "wsrUSD", 18),
    (999, address("0x1ac2ee68b8d038c982c1e1f73f596927dd70de59"), "LINK", 18),
    (999, address("0x211cc4dd073734da055fbf44a2b4667d5e5fe5d2"), "sUSDe", 18),
    (999, address("0x3073f7aaa4db83f95e9fff17424f71d4751a3073"), "MOVE", 8),
    (999, address("0x5555555555555555555555555555555555555555"), "WHYPE", 18),
    (999, address("0x5d3a1ff2b6bab83b63cd9ad0787074081a52ef34"), "USDe", 18),
    (999, address("0x9b498c3c8a0b8cd8ba1d9851d40d186f1872b44e"), "PURR", 18),
    (999, address("0x9ba2edc44e0a4632eb4723e81d4142353e1bb160"), "vkHYPE", 18),
    (999, address("0x9fdbda0a5e284c32744d2f17ee5c74b284993463"), "UBTC", 8),
    (999, address("0xa3d68b74bf0528fdd07263c60d6488749044914b"), "weETH", 18),
    (999, address("0xab11329560fa9c9c860bb21a9342215a1265bbb0"), "APE", 18),
    (999, address("0xae4efbc7736f963982aacb17efa37fcbab924cb3"), "solvBTC", 18),
    (999, address("0xb73ee5488647a6302ebf5fee8af3152f6960ae4c"), "WXRP", 6),
    (999, address("0xb88339cb7199b77e23db6e890353e22632ba630f"), "USDC", 6),
    (999, address("0xb8ce59fc3717ada4c02eadf9682a9e934f625ebb"), "USDT0", 6),
    (999, address("0xc12e26ab94d1e62f18373cf25e43afa7b2af1cdc"), "REKT", 18),
    (999, address("0xc99f5c922dae05b6e2ff83463ce705ef7c91f077"), "xSolvBTC", 18),
    (999, address("0xd6eb81136884713e843936843e286fd2a85a205a"), "PENDLE", 18),
    (999, address("0xdfc7d2d003a053b2e0490531e9317a59962b511e"), "brBTC", 8),
    (999, address("0xf4d9235269a96aadafc9adae454a0618ebe37949"), "XAUT0", 6),
    (999, address("0xf9775085d726e782e83585033b58606f7731ab18"), "uniBTC", 8),
    (999, address("0xfa44c2634ff17cbe26dc3007d36bd61c79068c14"), "PENGU", 18),
    (999, address("0xfd739d4e423301ce9385c1fb8850539d657c296d"), "kHYPE", 18),
    (999, address("0xfdd22ce6d1f66bc0ec89b20bf16ccb6670f55a5a"), "thBILL", 6),
    (999, address("0xffaa4a3d97fe9107cef8a3f48c069f577ff76cc1"), "stHYPE", 18),
    (5000, address("0x00000000efe302beaa2b3e6e1b18d08d69a9012a"), "AUSD", 6),
    (5000, address("0x075df695b8e7f4361fa7f8c1426c63f11b06e326"), "USDA", 18),
    (5000, address("0x09bc4e0d864854c6afb6eb9a9cdf58ac190d0df9"), "USDC", 6),
    (5000, address("0x111111d2bf19e43c34263401e0cad979ed1cdb61"), "USD1", 18),
    (5000, address("0x1d40bafc49c37cda49f2a5427e2fb95e1e3fcf20"), "xSolvBTC", 18),
    (5000, address("0x201eba5cc46d216ce6dc03f6a759e8e766e956ae"), "USDT", 6),
    (5000, address("0x211cc4dd073734da055fbf44a2b4667d5e5fe5d2"), "sUSDe", 18),
    (5000, address("0x4186bfc76e2e237523cbc30fd220fe055156b41f"), "rsETH", 18),
    (5000, address("0x58538e6a46e07434d7e7375bc268d3cb839c0133"), "ENA", 18),
    (5000, address("0x5be26527e817998a7206475496fde1e68957c5a6"), "USDY", 18),
    (5000, address("0x5d3a1ff2b6bab83b63cd9ad0787074081a52ef34"), "USDe", 18),
    (5000, address("0x779ded0c9e1022225f8e0630b35a9b54be713736"), "USDT0", 6),
    (5000, address("0x78c1b0c915c4faa5fffa6cabf0219da63d7f4cb8"), "WMNT", 18),
    (5000, address("0x93919784c523f39cacaa98ee0a9d96c3f32b593e"), "uniBTC", 8),
    (5000, address("0xa68d25fc2af7278db4bcdcaabce31814252642a9"), "solvBTC", 18),
    (5000, address("0xc96de26018a54d51c097160568752c4e3bd6c364"), "FBTC", 8),
    (5000, address("0xcda86a272531e8640cd7f1a92c01839911b90bb0"), "mETH", 18),
    (5000, address("0xdeaddeaddeaddeaddeaddeaddeaddeaddead1111"), "WETH", 18),
    (5000, address("0xe6829d9a7ee3040e1276fa75293bde931859e8fa"), "cmETH", 18),
    (5000, address("0xf3df0a31ec5ea438150987805e841f960b9471b6"), "WOO", 18),
    (5000, address("0xfe36cf0b43aae49fbc5cfc5c0af22a623114e043"), "LINK", 18),
    (8453, address("0x04c0599ae5a44757c0af6f9ec3b93da8976c150a"), "weETH", 18),
    (8453, address("0x0b3e328455c4059eeb9e3f84b5543f74e24e7e1b"), "VIRTUAL", 18),
    (8453, address("0x2416092f143378750bb29b79ed961ab195cceea5"), "ezETH", 18),
    (8453, address("0x2ae3f1ec7f1f5012cfeab0185bfc7aa3cf0dec22"), "cbETH", 18),
    (8453, address("0x4200000000000000000000000000000000000006"), "WETH", 18),
    (8453, address("0x4ed4e862860bed51a9570b96d89af5e1b0efefed"), "DEGEN", 18),
    (8453, address("0x50c5725949a6f0c72e6c4a641f24049a917db0cb"), "DAI", 18),
    (8453, address("0x532f27101965dd16442e59d40670faf5ebb142e4"), "BRETT", 18),
    (8453, address("0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"), "EURC", 6),
    (8453, address("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"), "USDC", 6),
    (8453, address("0x940181a94a35a4569e4529a3cdfb74e38fd98631"), "AERO", 18),
    (8453, address("0xb6fe221fe9eef5aba221c348ba20a1bf5e73624c"), "rETH", 18),
    (8453, address("0xbaa5cc21fd487b8fcc2f632f3f4e8d37262a0842"), "MORPHO", 18),
    (8453, address("0xc1cba3fcea344f92d9239c08c0568f6f2f0ee452"), "wstETH", 18),
    (8453, address("0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf"), "cbBTC", 8),
    (8453, address("0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca"), "USDbC", 6),
    (8453, address("0xfde4c96c8593536e31f229ea8f37b2ada2699bb2"), "USDT", 6),
    (9745, address("0x0a1a1a107e45b7ced86833863f482bc5f4ed82ef"), "USDai", 18),
    (9745, address("0x0b2b2b2076d95dda7817e785989fe353fe955ef9"), "sUSDai", 18),
    (9745, address("0x1b64b9025eebb9a6239575df9ea4b9ac46d4d193"), "XAUT0", 6),
    (9745, address("0x211cc4dd073734da055fbf44a2b4667d5e5fe5d2"), "sUSDe", 18),
    (9745, address("0x5d3a1ff2b6bab83b63cd9ad0787074081a52ef34"), "USDe", 18),
    (9745, address("0x6100e367285b01f48d07953803a2d8dca5d19873"), "WXPL", 18),
    (9745, address("0x61e030a56d33e8260fdd81f03b162a79fe3449cd"), "FLUID", 18),
    (9745, address("0x6eaf19b2fc24552925db245f9ff613157a7dbb4c"), "xUSD", 6),
    (9745, address("0x76a443768a5e3b8d1aed0105fc250877841deb40"), "LINK", 18),
    (9745, address("0x9895d81bb462a195b4922ed7de0e3acd007c32cb"), "WETH", 18),
    (9745, address("0x9ecaf80c1303cca8791afbc0ad405c8a35e8d9f1"), "rsETH", 18),
    (9745, address("0xa3d68b74bf0528fdd07263c60d6488749044914b"), "weETH", 18),
    (9745, address("0xb77e872a68c62cfc0dfb02c067ecc3da23b4bbf3"), "GHO", 18),
    (9745, address("0xb8ce59fc3717ada4c02eadf9682a9e934f625ebb"), "USDT0", 6),
    (9745, address("0xc4374775489cb9c56003bf2c9b12495fc64f0771"), "syrupUSDT", 6),
    (9745, address("0xca632fa58397391c750c13f935daa61abbe0baa6"), "EUL", 18),
    (42161, address("0x0c880f6761f1af8d9aa9c466984b80dab9a8c9e8"), "PENDLE", 18),
    (42161, address("0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f"), "WBTC", 8),
    (42161, address("0x35751007a407ca6feffe80b3cb397736d2cf4dbe"), "weETH", 18),
    (42161, address("0x498bf2b1e120fed3ad3d42ea2165e9b73f99c1e5"), "crvUSD", 18),
    (42161, address("0x539bde0d7dbd336b79148aa742883198bbf60342"), "MAGIC", 18),
    (42161, address("0x5979d7b546e38e414f7e9822514be443a4800529"), "wstETH", 18),
    (42161, address("0x82af49447d8a07e3bd95bd0d56f35241523fbab1"), "WETH", 18),
    (42161, address("0x912ce59144191c1204e64559fe8253a0e49e6548"), "ARB", 18),
    (42161, address("0xaf88d065e77c8cc2239327c5edb3a432268e5831"), "USDC", 6),
    (42161, address("0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"), "DAI", 18),
    (42161, address("0xf97f4df75117a78c1a5a0dbb814af92458539fb4"), "LINK", 18),
    (42161, address("0xfa7f8980b0f1e64a2062791cc3b0871572f1f7f0"), "UNI", 18),
    (42161, address("0xfc5a1a6eb076a2c7ad06ed22c90d7e710e35ad0a"), "GMX", 18),
    (42161, address("0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"), "USDT", 6),
    (42161, address("0xff970a61a04b1ca14834a43f5de4533ebddb5cc8"), "USDC.e", 6),
    (59144, address("0x176211869ca2b568f2a7d4ee941e073a821ee1ff"), "USDC", 6),
    (59144, address("0x1bf74c010e6320bab11e2e5a532b5ac15e0b8aa6"), "weETH", 18),
    (59144, address("0x2416092f143378750bb29b79ed961ab195cceea5"), "ezETH", 18),
    (59144, address("0x3aab2285ddcddad8edf438c1bab47e1a9d05a9b4"), "WBTC", 8),
    (59144, address("0x4af15ec2a0bd43db75dd04e62faa3b8ef36b00d5"), "DAI", 18),
    (59144, address("0xa219439258ca9da29e9cc4ce5596924745e12b93"), "USDT", 6),
    (59144, address("0xb5bedd42000b71fdde22d3ee8a79bd49a568fc8f"), "wstETH", 18),
    (59144, address("0xe5d7c2a44ffddf6b295a15c148167daaaf5cf34f"), "WETH", 18),
];

/// The token at `address` on `chain_id`, if this build knows it.
///
/// A miss is the ordinary case, not an error: the table is a few dozen well-known
/// contracts, and everything else is shown by address with its amount in raw units.
pub fn lookup(chain_id: u64, address: &[u8; 20]) -> Option<Token> {
    let key = (chain_id, *address);
    let i = TOKENS
        .binary_search_by(|(c, a, _, _)| (*c, *a).cmp(&key))
        .ok()?;
    let (_, _, symbol, decimals) = TOKENS[i];
    Some(Token { symbol, decimals })
}

/// Whether this build knows any token on `chain_id`.
///
/// For a screen that wants to say "nothing here is named on this chain" rather than
/// leaving a person to wonder whether the table was consulted.
pub fn knows_chain(chain_id: u64) -> bool {
    TOKENS.iter().any(|(c, _, _, _)| *c == chain_id)
}

/// How many rows this build carries.
pub fn known() -> usize {
    TOKENS.len()
}

/// Row `i`, for the test that checks every baked address finds itself.
#[cfg(test)]
pub(crate) fn at(i: usize) -> Option<(u64, [u8; 20], &'static str)> {
    TOKENS.get(i).map(|(c, a, s, _)| (*c, *a, *s))
}
