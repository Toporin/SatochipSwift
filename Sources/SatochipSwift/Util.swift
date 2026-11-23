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
        return hexString.lowercased()
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
        // sig is DER format: 30 <len> 02 <lr> <r> 02 <ls> <s>
        guard sigIn.count >= 2 else {
            throw UtilError.wrongSignatureLength(expected: 8, received: UInt8(sigIn.count))
        }
        var offset = 0
        if (sigIn[offset] != 0x30){
            throw UtilError.wrongSignatureFormat(expected: 0x30, received: sigIn[offset])
        }
        offset += 2 // skip sequence tag and length, not needed
        
        let (r, offsetAfterR) = try readDerInteger(sig: sigIn, offset: offset)
        let (s, _) = try readDerInteger(sig: sigIn, offset: offsetAfterR)
        
        return (r, s, r + s)
    }
    
    /// Reads one DER INTEGER starting at its 0x02 tag, and returns it right-aligned in 32 bytes with the offset just past it.
    ///
    /// DER integers are signed and minimally encoded: a 256-bit value may take 33 bytes (a leading 0x00 keeps it positive)
    /// or fewer than 32 (leading zero bytes are not emitted). The latter happens for about one signature component in 256.
    private func readDerInteger(sig: [UInt8], offset start: Int) throws -> ([UInt8], Int) {
        var offset = start
        guard offset + 2 <= sig.count else {
            throw UtilError.wrongSignatureLength(expected: 2, received: UInt8(clamping: max(sig.count - offset, 0)))
        }
        let tag = sig[offset]
        if (tag != 0x02){
            throw UtilError.wrongSignatureCheckbyte(expected: 0x02, received: tag)
        }
        var len = Int(sig[offset + 1])
        offset += 2
        guard offset + len <= sig.count else {
            throw UtilError.wrongSignatureLength(expected: UInt8(clamping: len), received: UInt8(clamping: sig.count - offset))
        }
        if len > 0 && sig[offset] == 0x00 { // strip the sign byte, if present
            offset += 1
            len -= 1
        }
        guard len <= 32 else {
            throw UtilError.wrongSignatureLength(expected: 0x20, received: UInt8(clamping: len))
        }
        let value = [UInt8](repeating: 0, count: 32 - len) + sig[offset ..< offset + len] // right-align, zero-pad
        return (value, offset + len)
    }
    
}
