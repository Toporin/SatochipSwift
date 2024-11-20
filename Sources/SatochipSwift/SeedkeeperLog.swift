//
//  File.swift
//  
//
//  Created by Satochip on 18/04/2024.
//

import Foundation

enum SeedkeeperLogError: Error {
    case wrongLogSize(String)
}

public struct SeedkeeperLog: Hashable {
    
    public static let logSize = 7 // bytes
    
    public var ins: UInt8 = 0 //SatocardINS
    public var sid1: Int = 0
    public var sid2: Int = 0
    public var sw: UInt16 = 0 // StatusWord
    public var uid = UUID() // ensure unicity
    
    public init(response: [UInt8]) throws {
        if response.count < SeedkeeperLog.logSize {
            print("Log record has the wrong length \(response.count), should be \(SeedkeeperLog.logSize)")
            throw SeedkeeperLogError.wrongLogSize("Log record has the wrong length \(response.count), should be \(SeedkeeperLog.logSize)")
        }
        
        ins = response[0] //SatocardINS(rawValue: response[0])
        sid1 = Int(response[1])*256 + Int(response[2])
        sid2 = Int(response[3])*256 + Int(response[4])
        sw = UInt16(response[5])*256 + UInt16(response[6]) //StatusWord(rawValue: UInt16(response[5])*256 + UInt16(response[6]))
    }
    
    public func toString() -> String {
        var txt = "ins: \(String(format:"%02X", ins)); sid1: \(sid1); sid2: \(sid2); sw12: \(String(format:"%04X", sw));"
        return txt
    }
}
