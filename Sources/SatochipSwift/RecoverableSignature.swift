//import Logging

//let //logger = Logger(label: "io.satochip.recoverablesig")

enum ECDSASignatureTag: UInt8 {
    case signatureTemplate = 0xA0
    case ecdsaTemplate = 0x30
}

public struct RecoverableSignature {
    public let publicKey: [UInt8]
    public let coordx:  [UInt8]
    public let recId: UInt8
    public let r: [UInt8]
    public let s: [UInt8]
    
    //public init(hash: [UInt8], data: [UInt8]) throws {
    public init(msg: [UInt8], sig: [UInt8], coordx: [UInt8]) throws {
        //logger.info("In RecoverableSignature")
        self.coordx = coordx
        let hash: [UInt8] = Crypto.shared.sha256(msg)
        //logger.info("Hash: \(hash.bytesToHex)")
        
        // let (self.r, self.s, _) = try Util.shared.parseToCompactSignature(sigIn: sig) // error 'expected pattern'
        let (r, s, _) = try Util.shared.parseToCompactSignature(sigIn: sig)
        self.r = r
        self.s = s
        //logger.info("R: \(self.r.bytesToHex)")
        //logger.info("S: \(self.s.bytesToHex)")
        
        var foundID: UInt8 = UInt8.max
        var foundPubkey: [UInt8] = []
        for i: UInt8 in 0...3 {
            let pub = Crypto.shared.secp256k1RecoverPublic(r: r, s: s, recId: i, hash: hash)
            let pubCoordx = Array(pub[1 ... 32])
            //logger.info("Recovered coordx: \(pubCoordx.bytesToHex)")
            if (pubCoordx == coordx) {
                foundPubkey = pub
                foundID = i
                //logger.info("Found pubkey: \(pub.bytesToHex)")
                break
            }
        }
        
        if (foundID != UInt8.max) {
            self.recId = foundID
            self.publicKey = foundPubkey
        } else {
            throw CardError.unrecoverableSignature
        }
    }
    
}
