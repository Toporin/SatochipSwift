enum UtilError: Error {
    case wrongSignatureFormat(expected: UInt8, received: UInt8)
    case wrongSignatureLength(expected: UInt8, received: UInt8)
    case wrongSignatureCheckbyte(expected: UInt8, received: UInt8)
}

public extension Collection where Element == Character {
    var hexToBytes: [UInt8] {
        var last = first
        return dropFirst().compactMap {
            guard
                let lastHexDigitValue = last?.hexDigitValue,
                let hexDigitValue = $0.hexDigitValue else {
                    last = $0
                    return nil
                }
            defer {
                last = nil
            }
            return UInt8(lastHexDigitValue * 16 + hexDigitValue)
        }
    }
}

extension Array where Element == UInt8 {
  func bytesToHexSpacing(spacing: String) -> String {
    var hexString: String = ""
    var count = self.count
    for byte in self
    {
        hexString.append(String(format:"%02X", byte))
        count = count - 1
        if count > 0
        {
            hexString.append(spacing)
        }
    }
    return hexString
  }
}

public extension Array where Element == UInt8 {
    var bytesToHex: String {
        var hexString: String = ""
        var count = self.count
        for byte in self
        {
            hexString.append(String(format:"%02X", byte))
            count = count - 1
        }
        return hexString
    }
}

extension ArraySlice where Element == UInt8 {
    var bytesToHex: String {
        var hexString: String = ""
        var count = self.count
        for byte in self
        {
            hexString.append(String(format:"%02X", byte))
            count = count - 1
        }
        return hexString
    }
}

// convert UInt32 to 4 UInt8 array
extension UInt32 {
    var toBytes: [UInt8] {
        var bigEndian = self.bigEndian
        let count = MemoryLayout<UInt32>.size
        let bytePtr = withUnsafePointer(to: &bigEndian) {
            $0.withMemoryRebound(to: UInt8.self, capacity: count) {
                UnsafeBufferPointer(start: $0, count: count)
            }
        }
        return Array(bytePtr)
    }
}

// convert 4 UInt8 array to UInt32
extension Array where Element == UInt8 {
    var toUInt32: UInt32 {
        var out : UInt32 = 0
        for byte in self[0 ... 3] {
            out = out << 8
            out = out | UInt32(byte)
        }
        return out
    }
}

// convert 4 UInt8 array to UInt32
extension ArraySlice where Element == UInt8 {
    var toUInt32: UInt32 {
        var out : UInt32 = 0
        for byte in self[0 ... 3] {
            out = out << 8
            out = out | UInt32(byte)
        }
        return out
    }
}

// extract a string from String
extension String {
    subscript (bounds: CountableClosedRange<Int>) -> String {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return String(self[start...end])
    }
    subscript (bounds: CountableRange<Int>) -> String {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return String(self[start..<end])
    }
}

extension Array {
    func chunked(into size: Int) -> [ArraySlice<Element>] {
        return stride(from: 0, to: count, by: size).map {
            self[$0 ..< Swift.min($0 + size, count)]
        }
    }
}

class Util {
    static let shared = Util()
    
    private init() {}
    
    func dropZeroPrefix(uint8: [UInt8]) -> [UInt8] {
        uint8[0] == 0x00 ? Array(uint8[1...]) : uint8
    }
    
    func parseToCompactSignature(sigIn: [UInt8]) throws -> ([UInt8], [UInt8], [UInt8]){
        //let sigInSize = sigIn.count
        
        var offset=0
        if (sigIn[offset] != 0x30){
            throw UtilError.wrongSignatureFormat(expected: 0x30, received: sigIn[offset])
        }
        offset+=1
        
        //let lt = sigIn[offset]
        offset+=1
        var check = sigIn[offset]
        if (check != 0x02){
            throw UtilError.wrongSignatureFormat(expected: 0x02, received: sigIn[offset])
        }
        offset+=1
        
        let lr = sigIn[offset] // should be 0x20 or 0x21 if first r msb is 1
        offset+=1
        let r: ArraySlice<UInt8>
        if (lr == 0x20){
            r = sigIn[offset ..< (offset+32)]
            offset+=32
        }else if (lr == 0x21){
            offset+=1 // skip zero byte
            r = sigIn[offset ..< (offset+32)]
            offset+=32
        }
        else{
            throw UtilError.wrongSignatureLength(expected: 0x20, received: lr)
        }
        
        check = sigIn[offset]
        offset+=1
        if (check != 0x02){
            throw UtilError.wrongSignatureCheckbyte(expected: 0x02, received: check)
            
        }
        
        let ls = sigIn[offset] // should be 0x20 or 0x21 if first s msb is 1
        offset+=1
        let s: ArraySlice<UInt8>
        if (ls == 0x20){
            s = sigIn[offset ..< (offset+32)]
            offset+=32
        } else if (ls == 0x21){
            offset+=1 // skip zero byte
            s = sigIn[offset ..< (offset+32)]
            offset+=32
        } else{
            throw UtilError.wrongSignatureLength(expected: 0x20, received: ls)
        }
        
        //let sigOutSize = 64
        let sigOut: ArraySlice<UInt8>
        sigOut = r + s
        
        //return sigOut;
        return (Array(r), Array(s), Array(sigOut))
    }
    
}
