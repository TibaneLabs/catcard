# Chain marks: where they came from

Each `<TICKER>.png` here is its project's logo, downscaled to 20x20 from the 250x250
image CoinGecko serves for the coin (`api.coingecko.com/api/v3/coins/<id>`, field
`image.large`), fetched 2026-09-22. `tools/artgen/chainmarks.py` quantizes the set to
the chain picker's shared palette. Tron's, served as a square with no transparency, was
cut to a circle like the rest.

The logos are their projects' trademarks, used here only to identify each chain in the
picker.

| mark | CoinGecko id | image |
|---|---|---|
| BTC | bitcoin | `coins/images/1/large/bitcoin.png` |
| ETH | ethereum | `coins/images/279/large/ethereum.png` |
| SOL | solana | `coins/images/4128/large/solana.png` |
| LTC | litecoin | `coins/images/2/large/litecoin.png` |
| BCH | bitcoin-cash | `coins/images/780/large/bitcoin-cash-circle.png` |
| DOGE | dogecoin | `coins/images/5/large/dogecoin.png` |
| TRX | tron | `coins/images/1094/large/photo_2026-04-13_09-59-16.png` |
| MONA | monacoin | `coins/images/99/large/monacoin.png` |
| XEP | electra-protocol | `coins/images/13589/large/Apple-iPhone-Icon-Retina.png` |

To replace one, drop a new 20x20 RGBA PNG here under the same name and re-run the
generator. The one-bit marks for the OLED are still drawn by the generator (a disc with
the letter knocked out): a logo at twelve pixels in one bit does not survive.
