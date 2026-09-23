// Solana mints this firmware can name.
//
// Every row is a claim about a mint, and a wrong one would let a hostile token borrow a
// familiar name at the moment somebody is deciding to sign. So **no address here was
// written from memory**: each was taken from Jupiter's verified token list and then
// confirmed, byte for byte and decimal for decimal, against a second source that shares
// no data with it -- the Solana Labs token list where it has the token, CoinGecko's
// by-contract lookup otherwise. Anything only one source knew was left out.
//
// Sources, fetched 2026-09-23:
//   https://lite-api.jup.ag/tokens/v2/  (verified flag, symbol, decimals)
//   https://raw.githubusercontent.com/solana-labs/token-list/main/src/tokens/solana.tokenlist.json
//   https://api.coingecko.com/api/v3/coins/solana/contract/<mint>
//
// Selection: the majors, the stables, the staked-SOL tokens, and anything with real
// liquidity behind it. Tokenised equities and pre-IPO paper are deliberately absent --
// real assets, but not what a wallet is asked to name.

export const SOLANA_MINTS = [
  M('JitoSOL', 'J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn', 9),  // confirmed by coingecko
  M('SOL', 'So11111111111111111111111111111111111111112', 9),  // confirmed by solana-labs
  M('USDC', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 6),  // confirmed by solana-labs
  M('mSOL', 'mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So', 9),  // confirmed by solana-labs
  M('bSOL', 'bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1', 9),  // confirmed by solana-labs
  M('USDG', '2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH', 6),  // confirmed by coingecko
  M('WBTC', '3NZ9JMVBmGAqocybic2c7LQCJScmgsAZ6vQqTDzcqmJh', 8),  // confirmed by solana-labs
  M('PUMP', 'pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn', 6),  // confirmed by coingecko
  M('PYUSD', '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo', 6),  // confirmed by coingecko
  M('USDT', 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', 6),  // confirmed by solana-labs
  M('ETH', '7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs', 8),  // confirmed by solana-labs
  M('RAY', '4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R', 6),  // confirmed by solana-labs
  M('USDS', 'USDSwr9ApdHk5bvJKMjzff41FfuX8bSxdKcR81vTwcA', 6),  // confirmed by coingecko
  M('aura', 'DtR4D9FtVoTX2569gaL837ZgrB6wNjj6tkmnX9Rdk9B2', 6),  // confirmed by coingecko
  M('EURC', 'HzwqbKZw8HxMN6bF2yFZNrht3c2iXXzpKcFu7uBEDKtr', 6),  // confirmed by coingecko
  M('JTO', 'jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL', 9),  // confirmed by coingecko
  M('PYTH', 'HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3', 6),  // confirmed by coingecko
  M('WIFE', '4y3oUrsJfSp431R3wJrWiaLxRPsnYtpkVJmoV2bYpBiy', 6),  // confirmed by coingecko
  M('$WIF', 'EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm', 6),  // confirmed by coingecko
  M('Bonk', 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263', 5),  // confirmed by coingecko
  M('Fartcoin', '9BB6NFEcjBCtnNLFko2FqVQBq8HHM13kCyYcdQbgpump', 6),  // confirmed by coingecko
  M('HYPE', '98sMhvDwXj1RQi5c5Mndm3vPe9cBqPrbLaufMXFNMh5g', 9),  // confirmed by coingecko
  M('JLP', '27G8MtK7VtTcCHkpASjSDdkWWYfoqT6ggEuKidVJidD4', 6),  // confirmed by coingecko
  M('JUP', 'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN', 6),  // confirmed by coingecko
  M('MET', 'METvsvVRapdj9cFLzq4Tr43xK4tAjQfwX76z3n6mWQL', 6),  // confirmed by coingecko
  M('PENGU', '2zMMhcVQEXDtdE6vsFS7S7D5oUodfJHE8vd1gnBouauv', 6),  // confirmed by coingecko
  M('USELESS', 'Dz9mQ9NzkBcCsuGPFJ3r1bS4wgqKMHBPiVuniW8Mbonk', 6),  // confirmed by coingecko
  M('ZEC', 'A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS', 8),  // confirmed by coingecko
];
