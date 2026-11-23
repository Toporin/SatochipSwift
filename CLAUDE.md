# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

SatochipSwift is a Swift Package (iOS 13+) SDK for talking to Satochip-family JavaCard smartcards over NFC: **Satochip** (hardware wallet), **Satodime** (bearer card), **Seedkeeper** (secret storage) and **Satocash** (Cashu ecash). It's loosely based on Keycard.swift. The Android/desktop equivalent is Satochip-Java. Card-side behavior is defined by the separate applet repos (SatochipApplet, Satodime-Applet, Seedkeeper-Applet).

## Build & test

The package depends on `CoreNFC`, so build it against an iOS destination. A plain `swift build` on macOS will fail.

Tests run on an iOS simulator. Select it by ID: `name=iPhone 15` fails here because xcodebuild can't resolve the name to a single destination. List the simulator IDs with `xcodebuild -scheme SatochipSwift -showdestinations`.

```sh
xcodebuild -scheme SatochipSwift -destination 'generic/platform=iOS' build
xcodebuild -scheme SatochipSwift -destination 'id=<simulator-id>' test
# single test:
xcodebuild -scheme SatochipSwift -destination 'id=<simulator-id>' test \
  -only-testing:SatochipSwiftTests/SatochipTests/testRecoverPubkeyFromRandomSignatures
```

`Tests/SatochipSwiftTests` covers only the pure crypto paths that don't need a card: DER signature parsing and public key recovery, exercised with real libsecp256k1 signatures. APDU commands need a physical card, so they have no automated coverage. No linter is configured.

## Architecture

The flow is: NFC session → `CardChannel` → `SatocardCommandSet` → parsers/status models.

- **`SatocardController`** wraps `NFCTagReaderSession`. When it detects an ISO7816 tag, it calls `onConnect` with a `CoreNFCCardChannel`.
- **`CardChannel`** is a one-method protocol (`send(APDUCommand) -> APDUResponse`), so you can swap the transport (for example, to mock it).
- **`SatocardCommandSet`** (`SatocardCommandSet.swift`, about 2.5k lines) holds nearly all of the logic. It has one public method per applet instruction, grouped by `MARK:` sections (common, Satochip/BIP32/signing, Satodime, Seedkeeper, Satocash, PKI/authenticity). Method prefixes show which card they target: `card*` for common commands and Satochip, then `satodime*`, `seedkeeper*` and `satocash*`.
  - `selectApplet(cardType:)` selects by AID. With `.anycard` it tries each AID in turn. On newer cards, the SELECT response already includes the status, which then populates `cardStatus`.
  - Almost every command goes through **`cardTransmit(plainApdu:)`**. It fetches the status if needed and opens the ECDH/AES **secure channel** (`SecureChannel.swift`) when `cardStatus.needsSecureChannel` is true. It encrypts every instruction except those in `plainInstructionSet`. It also retries automatically on SW `0x9C06` (PIN required, re-verifies with the cached `pin0`) and on `0x9C21` (secure channel reset).
  - `sensitiveInstructionSet` lists the instructions whose APDU payloads get masked in debug `print` logging. Add any new instruction that carries secrets to this set.
- **`SatocardParser`** decodes complex responses: secure-channel init and authentikey recovery, BIP32 extended keys, Satodime keys and signatures.
- **Status/data models** (`CardStatus`, `SatodimeStatus`, `SeedkeeperStatus`, `SatocashStatus`, `Seedkeeper*`, `Satocash*`) are built from `APDUResponse` bytes. `CardStatus` exposes `protocolVersion` as `(major << 8) | minor` plus capability flags (for example, `supportsTaproot`).
- **`APDUResponse.checkOK()` / `checkAuthOK()` / `checkSW(...)`** turn status words into thrown `StatusWord`/`CardError` values. `StatusWord.swift` and `Satocard.swift` define the INS codes, AIDs and SW constants.
- **`Certificates.swift`** plus `cardVerifyAuthenticity()` verify the card's PKI certificate chain (uses SwiftTLS) against embedded root/sub CAs.
- Crypto helpers live in `Crypto.swift`, `RIPEMD160.swift`, `Base58.swift`, `BIP32KeyPair.swift`, `Mnemonic*.swift` and `RecoverableSignature.swift`. They build on secp256k1.swift, CryptoSwift and BigInt.

## Conventions

- **Feature gating by applet version.** A command that requires a newer applet should check `cardStatus.protocolVersion` and throw `SatocardError.unsupportedFeature` when the card is too old. If `cardStatus` is nil, fetch it first (see `cardTaprootTweakPrivateKey`). Error enums (`SatocardError`, `SeedkeeperApiError`, …) are declared at the top of `SatocardCommandSet.swift`.
- **Public API docs.** New public methods use `/** ... - Parameter / - Returns / - Throws */` doc comments, with the APDU data layout noted inline (for example, `// data: [tweak_size(1b) | tweak_data]`).
- **Releases.** Bump `SATOCHIPSWIFT_*_VERSION` in `Version.swift` and add a note in the comment list there, and add an entry to `CHANGELOG.md` (Keep a Changelog / SemVer). Also update the supported-protocol constants in `Version.swift` when adding support for a new applet version.
- **Dependencies.** Pin them to tagged versions (`upToNextMinor`/`upToNextMajor`), never branches, because branch pins break consumers that depend on tagged releases.
