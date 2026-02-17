//
//  SatocashStatus.swift
//  SatochipSwift
//
//  Created by Satochip on 28/03/2025.
//
public struct SatocashStatus {

    public var setupDone: Bool = false
    public var isSeeded: Bool = false
    public var needsSecureChannel: Bool = false
    public var needs2FA: Bool = false
    public var protocolMajorVersion: UInt8 = 0
    public var protocolMinorVersion: UInt8 = 0
    public var appletMajorVersion: UInt8 = 0
    public var appletMinorVersion: UInt8 = 0
    public var pin0RemainingTries: UInt8 = 0
    public var puk0RemainingTries: UInt8 = 0
    public var pin1RemainingTries: UInt8 = 0
    public var puk1RemainingTries: UInt8 = 0
    public var protocolVersion: UInt16 = 0
    
    public var nfcPolicy: UInt8 = 0
    public var pinPolicy: UInt8 = 0
    public var rfuPolicy: UInt8 = 0
    public var max_nb_mints: UInt8 = 0
    public var nb_mints: UInt8 = 0
    public var max_nb_keysets: UInt8 = 0
    public var nb_keysets: UInt8 = 0
    public var max_nb_proofs: UInt16 = 0
    public var nb_unspent_proofs: UInt16 = 0
    public var nb_spent_proofs: UInt16 = 0
    public var nb_proofs: UInt16 = 0
    
    public init?(rapdu: APDUResponse) {
        
        if (rapdu.sw == 0x9000) && (rapdu.data.count >= 4) {
            
            let data = rapdu.data
            // version
            protocolMajorVersion = data[0]
            protocolMinorVersion = data[1]
            appletMajorVersion = data[2]
            appletMinorVersion = data[3]
            protocolVersion = UInt16(protocolMajorVersion<<8) + UInt16(protocolMinorVersion)
            
            // pin status
            if data.count >= 8 {
                pin0RemainingTries = data[4]
                puk0RemainingTries = data[5]
                pin1RemainingTries = data[6]
                puk1RemainingTries = data[7]
                needs2FA = false //default value
            }
            // 2FA
            if data.count >= 9 {
                needs2FA = (data[8]==0x00 ? false : true)
            }
            // RFU
            if data.count >= 10 {
                isSeeded = (data[9]==0x00 ? false : true)
            }
            // setup status
            if data.count >= 11 {
                setupDone = (data[10]==0x00 ? false : true)
            } else {
                setupDone = true
            }
            // secure channel
            if data.count >= 12 {
                needsSecureChannel = (data[11]==0x00 ? false : true)
            } else {
                needsSecureChannel = false
                needs2FA = false //default value
            }
            // NFC policy
            if data.count >= 13 {
                nfcPolicy = data[12]  // 0:NFC_ENABLED, 1:NFC_DISABLED, 2:NFC_BLOCKED
            } else {
                nfcPolicy = 0x00  // NFC_ENABLED by default
            }
            // pin policy
            pinPolicy = data[13]
            // RFU policy
            rfuPolicy = data[14]
            // satocash settings
            max_nb_mints = data[15]
            nb_mints = data[16]
            max_nb_keysets = data[17]
            nb_keysets = data[18]
            max_nb_proofs = UInt16((data[19]<<8) + data[20])
            nb_unspent_proofs = UInt16((data[21]<<8) + data[22])
            nb_spent_proofs = UInt16((data[23] << 8) + data[24])
            nb_proofs = nb_unspent_proofs + nb_spent_proofs
            
        } else if rapdu.sw==0x9c04 {
            setupDone = false
            isSeeded = false
            needsSecureChannel = false
        } else {
            // NOTE: this is a breaking change compared to v0.1.0
            return nil
        }
    }

    public func toString() -> String {
        let status_info: String =   "setup_done: \(setupDone) \n" +
                                    "is_seeded: \(isSeeded) \n" +
                                    "needs_2FA: \(needs2FA) \n" +
                                    "needs_secure_channel: \(needsSecureChannel) \n" +
                                    "protocol_major_version: \(protocolMajorVersion) \n" +
                                    "protocol_minor_version: \(protocolMinorVersion) \n" +
                                    "applet_major_version: \(appletMajorVersion) \n" +
                                    "applet_minor_version: \(appletMinorVersion) \n" +
                                    "nfcPolicy: \(nfcPolicy) \n" +
                                    "pinPolicy: \(pinPolicy) \n" +
                                    "rfuPolicy: \(rfuPolicy) \n" +
                                    "satocash_max_nb_mints: \(max_nb_mints) \n" +
                                    "satocash_nb_mints: \(nb_mints) \n" +
                                    "satocash_max_nb_keysets: \(max_nb_keysets) \n" +
                                    "satocash_nb_keysets: \(nb_keysets) \n" +
                                    "satocash_max_nb_proofs: \(max_nb_proofs) \n" +
                                    "satocash_nb_unspent_proofs: \(nb_unspent_proofs) \n" +
                                    "satocash_nb_spent_proofs: \(nb_spent_proofs) \n" +
                                    "satocash_nb_proofs: \(nb_proofs)"
        
        return status_info
    }
    
}

