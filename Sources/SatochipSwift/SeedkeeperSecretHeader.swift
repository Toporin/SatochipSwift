//
//  SeedkeeperSecretHeader.swift
//
//
//  Created by Satochip on 26/03/2024.
//

import Foundation

public enum SeedkeeperExportRights: UInt8 {
    case exportForbidden = 0x00
    case exportPlaintextAllowed = 0x01
    case exportEncryptedOnly = 0x02
    case exportAuthenticatedOnly = 0x03
}

public enum SeedkeeperSecretOrigin: UInt8 {
    case plainImport = 0x01
    case encryptedImport = 0x02
    case generatedOnCard = 0x03
}

public enum SeedkeeperSecretType: UInt8 {
    case defaultType = 0x00
    case masterseed = 0x10
    case bip39Mnemonic = 0x30
    case electrumMnemonic = 0x40
    case shamirSecretShare = 0x50
    case privkey = 0x60
    case pubkey = 0x70
    case pubkeyAuthenticated = 0x71
    case key = 0x80
    case password = 0x90
    case masterPassword = 0x91
    case certificate = 0xA0
    case secret2FA = 0xB0
    case data = 0xC0
    case walletDescriptor = 0xC1
}

public enum SeedkeeperSecretSubtype: UInt8 {
    case defaultSubtype = 0x00
}

public enum SeedkeeperMasterseedSubtype: UInt8 {
    case defaultSubtype = 0x00
    case bip39Mnemonic = 0x01
}

public enum SeedkeeperKeySubtype: UInt8 {
    case defaultSubtype = 0x00
    case entropy = 0x10
}

public struct SeedkeeperSecretHeader : Hashable {
    
    public static let HEADER_SIZE = 13
    
    public var sid = 0
    public var type = SeedkeeperSecretType.defaultType
    public var subtype: UInt8 = UInt8(0) // todo: 
    public var origin = SeedkeeperSecretOrigin.plainImport
    public var exportRights = SeedkeeperExportRights.exportPlaintextAllowed
    public var nbExportPlaintext: UInt8 = UInt8(0)
    public var nbExportEncrypted: UInt8 = UInt8(0)
    public var useCounter: UInt8 = UInt8(0)
    public var rfu2: UInt8 = UInt8(0) // currently not used
    public var fingerprintBytes = [UInt8](repeating: 0, count: 4)
    public var label = ""
    
    public init(sid: Int = 0,
                type: SeedkeeperSecretType = SeedkeeperSecretType.defaultType,
                subtype: UInt8 = UInt8(0),
                origin: SeedkeeperSecretOrigin = SeedkeeperSecretOrigin.plainImport,
                exportRights: SeedkeeperExportRights = SeedkeeperExportRights.exportPlaintextAllowed,
                nbExportPlaintext: UInt8 = UInt8(0),
                nbExportEncrypted: UInt8 = UInt8(0),
                useCounter: UInt8 = UInt8(0),
                rfu2: UInt8 = UInt8(0),
                fingerprintBytes: [UInt8] = [UInt8](repeating: 0, count: 4),
                label: String = "") {
        self.sid = sid
        self.type = type
        self.subtype = subtype
        self.origin = origin
        self.exportRights = exportRights
        self.nbExportPlaintext = nbExportPlaintext
        self.nbExportEncrypted = nbExportEncrypted
        self.useCounter = useCounter
        self.rfu2 = rfu2
        self.fingerprintBytes = fingerprintBytes
        self.label = label
    }
    
    public init(response: [UInt8]) throws{
        
        let responseLength: Int = response.count
        if (responseLength<SeedkeeperSecretHeader.HEADER_SIZE+2){
            throw SatocardError.wrongResponseLength(length: responseLength, expected: SeedkeeperSecretHeader.HEADER_SIZE+2)
        }
        
        var offset = 0
        sid = 256*Int(response[0]) + Int(response[1])
        type = SeedkeeperSecretType(rawValue: response[2]) ?? SeedkeeperSecretType.defaultType //use default if unknown
        subtype = response[12]
        origin = SeedkeeperSecretOrigin(rawValue: response[3]) ?? SeedkeeperSecretOrigin.plainImport //use default if unknown
        exportRights = SeedkeeperExportRights(rawValue: response[4]) ?? SeedkeeperExportRights.exportPlaintextAllowed //use default if unknown
        nbExportPlaintext = response[5]
        nbExportEncrypted = response[6]
        useCounter =  response[7]
        fingerprintBytes = Array(response[8..<12])
        rfu2 = response[13]
        let labelSize = Int(response[14])
        if (responseLength<SeedkeeperSecretHeader.HEADER_SIZE+2+labelSize){
            throw SatocardError.wrongResponseLength(length: responseLength, expected: SeedkeeperSecretHeader.HEADER_SIZE+2+labelSize)
        }
        let labelBytes = Array(response[15..<(15+labelSize)])
        label = String(decoding: labelBytes, as: UTF8.self)
    }
    
    public func getHeaderBytes() -> [UInt8] {
        let labelBytes = Array(label.utf8)
        let labelSize = UInt8(labelBytes.count)
        return [type.rawValue, origin.rawValue, exportRights.rawValue, nbExportPlaintext, nbExportEncrypted, useCounter] +
                fingerprintBytes +
                [subtype, rfu2, labelSize] +
                labelBytes
    }
    
    public static func getFingerprintBytes(secretBytes: [UInt8]) -> [UInt8] {
        let secretHash = Crypto.shared.sha256(secretBytes)
        let fingerprintFromSecret = Array(secretHash[0..<4])
        return fingerprintFromSecret
    }
    
}
