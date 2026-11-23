# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

Port from Satochip-Java (0.2.6, 0.3.5):
* Fix `cardUnblockPIN(puk:)` for Satochip v0.16, which expects the payload `[PUK_size(1b) | PUK | (optional) PIN_size(1b) | PIN]`. The format is selected from the card type and protocol version: earlier Satochip versions, Seedkeeper and Satodime keep the bare-PUK payload.
* Add an optional `newPin` parameter to `cardUnblockPIN(puk:newPin:)` to replace the PIN while unblocking (Satochip v0.16+ only, throws otherwise).
* Add `cardResetFactoryV3()`: single-command factory reset of Satochip v0.16+ (ins 0xFD, p1 0xAA, p2 0x55), sent through the secure channel, requiring neither PIN nor blocked PUK. The legacy `cardSendResetCommand()` is unchanged.

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

## [0.2.2]

Fix SwiftTLS version dependency: use tagged version instead of branch reference, which is not recommended or may cause issues with tagged version in dependent projects.

## [0.2.1]

Fix secp256k1 version dependency 

## [0.2.0]

Add Seedkeeper support
                                          
## [0.1.0]

Initial version
