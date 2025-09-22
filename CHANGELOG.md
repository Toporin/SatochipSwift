# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.3.3]

Support for Satodime v0.2+:
* Add SatodimeStatus isFixedCvc & isCoa fields
* Update repo for package secp256k1
* Update repo for package CryptoSwift

## [0.3.2]

Add ECDSA, Schnorr & Musig2 signatures support for Satochip:
* cardSignTransactionHash(keynbr: UInt8, txhash: [UInt8], chalresponse: [UInt8]?) throws -> [UInt8]
* cardTaprootTweakPrivateKey(keynbr: Int, tweak: [UInt8], bypassFlag: Bool) throws -> [UInt8]
* cardSignSchnorrHash(txhash: [UInt8], chalresponse: [UInt8]?) throws -> [UInt8]
* cardMusig2GenerateNonce(keynbr: Int, aggpk: [UInt8], msg: [UInt8], extra: [UInt8]) throws -> ([UInt8], [UInt8])
* cardMusig2Sign(keynbr: Int, secnonce: [UInt8], b: [UInt8], ea: [UInt8], rHasEvenY: Bool, ggaccIs1: Bool) throws -> [UInt8]

## [0.3.0]

Add Satocash support

## [0.2.0]

Add Seedkeeper support
                                          
## [0.1.0]

Initial version
