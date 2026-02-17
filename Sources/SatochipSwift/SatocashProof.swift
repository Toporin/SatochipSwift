//
//  SatocashProof.swift
//  SatochipSwift
//
//  Created by Satochip on 28/03/2025.
//
import Foundation

public enum SatocashUnit: UInt8 {
    case sat = 0x01
    case msat = 0x02
    case USD = 0x03
    case EUR = 0x04
}

public enum SatocashInfoType: UInt8 {
    case STATE = 0x00
    case KEYSET_INDEX = 0x01
    case AMOUNT_EXPONENT = 0x02
    case MINT_INDEX = 0x03
    case UNIT = 0x04
}

public struct SatocashProof {
    
    public static let MASK_SPENT_STATUS: UInt8 = 0x03
    public static let MASK_P2PK_STATUS: UInt8 = 0x80
    
    public var index: UInt16 = 0
    public var state: UInt8 = 0
    public var is_p2pk: Bool = false
    public var keysetIndex: UInt8 = 0
    public var amountExponent: UInt8 = 0
    public var amount: Int = 0
    public var secret: [UInt8]
    public var unblindedKey: [UInt8]
    
    public init?(bytes: [UInt8]) {
        
        // response format [proof_index(2b) | proof_state(1b) | keyset_index(1b) | amount_exponent(1b) | unblinded_key(33b) | secret(32b)]
        if (bytes.count >= 70){
            index = UInt16(bytes[0]<<8 + bytes[1])
            state = (bytes[2] & SatocashProof.MASK_SPENT_STATUS) // extract 2 least significant bits as proof spent status (empty/unspent/spent/rfu)
            is_p2pk = ((bytes[2] & SatocashProof.MASK_P2PK_STATUS)==SatocashProof.MASK_P2PK_STATUS) //extract most significant bit as P2PK flag
            keysetIndex = bytes[3]
            amountExponent = bytes[4] // todo check and parse?
            if (state == 0x00) || (amountExponent == 0xFF){
                amount = 0
            } else if (state == 0x02) || (amountExponent & 0x80 == 0x80) {
                // spent amount
                amount = -Int(pow(Double(2), Double(amountExponent)))
            } else {
                amount = Int(pow(Double(2), Double(amountExponent)))
            }
            
            unblindedKey = Array(bytes[5..<38])
            secret = Array(bytes[38..<70])
            
        } else {
            return nil
        }
    }
    
    public func toString() -> String {
        return "index: \(index) \n" +
                "state: \(state) \n" +
                "is_p2pk: \(is_p2pk) \n" +
                "keysetIndex: \(keysetIndex) \n" +
                "amountExponent: \(amountExponent) \n" +
                "amount: \(amount) \n" +
                "secret: \(secret.bytesToHex) \n" +
                "unblindedKey: \(unblindedKey.bytesToHex) \n"
    }
}
