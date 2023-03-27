//import CryptoSwift
import Foundation

class SecureChannel {
    //static let secretLength = 32
    //static let blockLength = 16
    static let pairingMaxClientCount = 5 // todo remove
    static let payloadMaxSize = 223 // todo check?
    
    static let secretLength = 16
    static let blockLength = 16
    static let ivSize = 16
    static let macSize = 20
    static let msgScKey:[UInt8] = [UInt8]("sc_key".utf8)
    static let msgScMac:[UInt8] = [UInt8]("sc_mac".utf8)
    
    var open: Bool
    var publicKey: [UInt8]?
    //var pairing: Pairing? // todo remove
    var secret: [UInt8]? // todo private?
    
    //private var ivCounter: UInt
    private var iv: [UInt8]
    private var ivCounter: UInt32
    private var sessionEncKey: [UInt8]
    private var sessionMacKey: [UInt8]
    private var privKey: [UInt8]?
    
    init() {
        open = false
        ivCounter = 0
        iv = []
        sessionEncKey = []
        sessionMacKey = []
    }
    
    func generateClientKeypair() -> [UInt8]{
        let (clientPrivKey, clientPubKey) = Crypto.shared.secp256k1GeneratePair()
        self.publicKey = clientPubKey
        self.privKey = clientPrivKey
        return publicKey!
    }
    
    // todo remove?
    func getClientPublicKey() -> [UInt8]{
        return publicKey!
    }
    
    func initiateSecureChannel(cardPubKey: [UInt8]) {
        //logger.info("In initiateSecureChannel")
        //logger.info("cardPubKey: \(cardPubKey.bytesToHex)")
        self.secret = Crypto.shared.secp256k1ECDH(privKey: self.privKey!, pubKey: cardPubKey)
        //logger.info("secret: \(self.secret!.bytesToHex)")
        
//        // debug: using compressed key => give same secret
//        let coordx = cardPubKey[1 ... 32]
//        let parity = cardPubKey[64]%2 == 0 ? UInt8(0x02) : UInt8(0x03)
//        let cardPubkeyComp = [parity] + coordx
//        let secret2 = Crypto.shared.secp256k1ECDH(privKey: self.privKey!, pubKey: cardPubkeyComp)
//        //logger.info("secret2: \(secret2.bytesToHex)")
        
        // derive session keys
        let sessionEncKeyTmp: [UInt8] = Crypto.shared.hmacSHA1(data: SecureChannel.msgScKey, key: self.secret!)
        sessionEncKey = Array(sessionEncKeyTmp[0 ..< 16]) // keep first 16 bytes only
        sessionMacKey = Crypto.shared.hmacSHA1(data: SecureChannel.msgScMac, key: self.secret!)
        //logger.info("msgScKey: \(SecureChannel.msgScKey.bytesToHex)")
        //logger.info("sessionEncKey: \(sessionEncKey.bytesToHex)")
        //logger.info("msgScMac: \(SecureChannel.msgScMac.bytesToHex)")
        //logger.info("sessionMacKey: \(sessionMacKey.bytesToHex)")
        ivCounter = 1
        open = true
    }
    
    func reset() {
        open = false
    }
    
    func encryptSecureChannel(plainApdu: APDUCommand) -> APDUCommand {
       
        let plainBytes: [UInt8] = plainApdu.serialize()
        
        // set iv
        var iv: [UInt8] = Crypto.shared.random(count: (SecureChannel.blockLength-4))
        let ivCounterBytes: [UInt8] = ivCounter.toBytes
        iv = iv + ivCounterBytes
        //logger.info("ivCounter: \(ivCounter)")
        //logger.info("ivCounterBytes: \(ivCounterBytes.bytesToHex)")
        //logger.info("iv: \(iv.bytesToHex)")
        ivCounter+=2
        
        // encrypt data
        precondition(plainBytes.count <= SecureChannel.payloadMaxSize)
        let encryptedBytes: [UInt8] = Crypto.shared.aes256Enc(data: plainBytes, iv: iv, key: self.sessionEncKey)
        //let encryptedBytes: [UInt8] = Crypto.shared.aes256EncNopad(data: Crypto.shared.pkcs7Pad(data: plainBytes, blockSize: SecureChannel.blockLength), iv: iv, key: self.sessionEncKey)
        //logger.info("encryptedBytes: \(encryptedBytes.bytesToHex)")
        
        // mac
        let dataToMac: [UInt8] = iv + [UInt8(encryptedBytes.count>>8), UInt8(encryptedBytes.count%0xff)] + encryptedBytes
        //logger.info("dataToMac: \(dataToMac.bytesToHex)")
        let macBytes: [UInt8] = Crypto.shared.hmacSHA1(data: dataToMac, key: sessionMacKey)
        
        // combine
        // data= iv + encryped_size + encrypted + mac_size + mac
        let dataBytes: [UInt8] = dataToMac + [UInt8(macBytes.count>>8), UInt8(macBytes.count&0xff)] + macBytes
        //logger.info("dataBytes: \(dataBytes.bytesToHex)")
        
        // convert to C-APDU and return
        let encryptedApdu = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.processSecureChannel.rawValue, p1: 0x00, p2: 0x00, data: dataBytes)
        return encryptedApdu;
    }
    
    func decryptSecureChannel(encryptedApdu: APDUResponse) throws -> APDUResponse {
        
        let encryptedBytes: [UInt8] = encryptedApdu.data
        if encryptedBytes.count==0{
            return encryptedApdu; // no decryption needed
        } else if (encryptedBytes.count<18){
            throw SecureChannelError.wrongEncryptedResponseLength(length: encryptedBytes.count)
        }
        var offset: Int = 0
        
        // iv
        let ivBytes = Array(encryptedBytes[0 ..< SecureChannel.ivSize])
        offset+=SecureChannel.ivSize
        //logger.info("ivBytes: \(ivBytes.bytesToHex)")
        
        // ciphertext
        let ciphertextSize: Int = (Int(encryptedBytes[offset] & UInt8(0xff))<<8) + Int(encryptedBytes[offset+1] & 0xff)
        offset+=2
        if (encryptedBytes.count - offset) != ciphertextSize {
            throw SecureChannelError.wrongEncryptedResponseLength(length: encryptedBytes.count)
        }
        let ciphertextBytes: [UInt8] = Array(encryptedBytes[offset ..< (offset+ciphertextSize)])
        //logger.info("ciphertextBytes: \(ciphertextBytes.bytesToHex)")
        
        // decrypt data
        let decryptedBytes: [UInt8] = Crypto.shared.aes256Dec(data: ciphertextBytes, iv: ivBytes, key: self.sessionEncKey)
        //logger.info("decryptedBytes: \(decryptedBytes.bytesToHex)")
    
        let plainResponse: APDUResponse = APDUResponse(sw1: 0x90, sw2: 0x00, data: decryptedBytes)
        
        return plainResponse
    }
}
