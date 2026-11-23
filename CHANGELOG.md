# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.3.4]

Satochip v0.16 support:
* Bump the supported Satochip protocol version (`Version.SATOCHIP_PROTOCOL_MINOR_VERSION`) from 0.15 to 0.16.
* Make `cardTaprootTweakPrivateKey()`, `cardMusig2GenerateNonce()` and `cardMusig2Sign()` public.
* `cardTaprootTweakPrivateKey()` accepts an empty tweak (BIP86, no script tree) as well as a 32-byte Merkle root, and throws `unsupportedFeature` when tweaking on an applet older than protocol 0.16.
* Add `CardStatus.supportsTaproot` and `supportsTaprootMultisig`, read from the card policy bytes on protocol 0.16+.
* Add `cardBip32ImportSeed(masterseed:)`, which checks the seed length (16-64 bytes), and `cardResetSeed(pin:chalresponse:)`, which checks the PIN (4-16 bytes) and challenge-response (20 bytes) lengths.
* Fix `CardStatus.needs2FA` being reset to false on cards whose status reports 2FA but has no secure-channel byte (older applets).

Port from Satochip-Java (0.2.6, 0.3.5):
* Fix `cardUnblockPIN(puk:)` for Satochip v0.16, which expects the payload `[PUK_size(1b) | PUK | (optional) PIN_size(1b) | PIN]`. The format is selected from the card type and protocol version: earlier Satochip versions, Seedkeeper and Satodime keep the bare-PUK payload.
* Add an optional `newPin` parameter to `cardUnblockPIN(puk:newPin:)` to replace the PIN while unblocking (Satochip v0.16+ only, throws otherwise).
* Add `cardResetFactoryV3()`: single-command factory reset of Satochip v0.16+ (ins 0xFD, p1 0xAA, p2 0x55), sent through the secure channel, requiring neither PIN nor blocked PUK. The legacy `cardSendResetCommand()` is unchanged.
* Fix an intermittent failure in every command that recovers a public key from a signature, including `cardInitiateSecureChannel()`: the DER parser only accepted 32- or 33-byte integers, but DER is minimally encoded and about one signature component in 256 is shorter. Integers of any length up to 32 bytes are now right-aligned and zero-padded.
* Public key recovery now checks the libsecp256k1 return codes and skips recovery ids that yield no point, instead of serializing an invalid public key.

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
