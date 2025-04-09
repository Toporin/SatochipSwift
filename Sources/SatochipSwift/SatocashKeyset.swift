//
//  SatocashParser.swift
//  SatochipSwift
//
//  Created by Satochip on 28/03/2025.
//

public struct SatocashKeyset {
    public let index: UInt8
    public let id: [UInt8]
    public let mintIndex: UInt8
    public let unit: UInt8
    
    public init(index: UInt8, id: [UInt8], mintIndex: UInt8, unit: UInt8) {
        self.index = index
        self.id = id
        self.mintIndex = mintIndex
        self.unit = unit
    }
    
    public init(bytes: [UInt8]) {
        self.index = bytes[0]
        self.id = Array(bytes[1..<9])
        self.mintIndex = bytes[9]
        self.unit = bytes[10]
    }
    
    public var idHex: String {
        return id.bytesToHex
    }
}


