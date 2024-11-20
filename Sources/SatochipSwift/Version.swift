//
//  Version.swift
//  
//
//  Created by Satochip on 10/02/2023.
//

import Foundation

// Version of supported cards
public struct Version {
    
    // Satochip supported version tuple
    // v0.4: getBIP32ExtendedKey also returns chaincode
    // v0.5: Support for Segwit transaction
    // v0.6: bip32 optimization: speed up computation during derivation of non-hardened child
    // v0.7: add 2-Factor-Authentication (2FA) support
    // v0.8: support seed reset and pin change
    // v0.9: patch message signing for alts
    // v0.10: sign tx hash
    // v0.11: support for (mandatory) secure channel
    // v0.12: card label & support for encrypted seed import from Seedkeeper
    public static let SATOCHIP_PROTOCOL_MAJOR_VERSION = 0
    public static let SATOCHIP_PROTOCOL_MINOR_VERSION = 0
    public static let SATOCHIP_PROTOCOL_VERSION = (SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+SATOCHIP_PROTOCOL_MINOR_VERSION

    // Seedkeeper supported version tuple
    // v 0.1: initial version
    public static let SEEDKEEPER_PROTOCOL_MAJOR_VERSION = 0
    public static let SEEDKEEPER_PROTOCOL_MINOR_VERSION = 2
    public static let SEEDKEEPER_PROTOCOL_VERSION = (SEEDKEEPER_PROTOCOL_MAJOR_VERSION<<8)+SEEDKEEPER_PROTOCOL_MINOR_VERSION

    // Satodime supported version tuple
    // v 0.1: initial version
    public static let SATODIME_PROTOCOL_MAJOR_VERSION = 0
    public static let SATODIME_PROTOCOL_MINOR_VERSION = 1
    public static let SATODIME_PROTOCOL_VERSION = (SATODIME_PROTOCOL_MAJOR_VERSION<<8)+SATODIME_PROTOCOL_MINOR_VERSION

    // SatochipSwift version
    // v0.1.0 initial version (satodime only)
    // v0.2.0 add Seedkeeper support
    public static let SATOCHIPSWIFT_MAJOR_VERSION = 0
    public static let SATOCHIPSWIFT_MINOR_VERSION = 2
    public static let SATOCHIPSWIFT_REVISION = 0
    public static let SATOCHIPSWIFT_VERSION = String(SATOCHIPSWIFT_MAJOR_VERSION) + "." + String(SATOCHIPSWIFT_MINOR_VERSION) + "." + String(SATOCHIPSWIFT_REVISION)
}
