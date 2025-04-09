import Foundation
import CryptoSwift
//import Logging

public enum ParserError: Error {
    case parseSatodimeGetPubkeyWrongDataLength(length: Int, expected: Int)
    case parseSatodimeGetPrivkeyWrongDataLength(length: Int, expected: Int)
    case parseSatodimeGetPrivkeyWrongSw(sw: UInt16)
    case parseVerifyChallengeResponsePersoWrongDataLength(length: Int, expected: Int)
    
    case failedToParseBip32Path(path: String)
    case failedToRecoverAuthentikey(recovered: String, expected: String)
    case authentikeyNotSet
    case missingSignature
    
}

public class SatocardParser {
    //let //logger = Logger(label: "io.satochip.parser")
    
    // todo: make methods static?
    
    public init() {}
    
    // Recover card pubkey and a list of potential authentikeys
    // The list of potential authentikeys contains 1 or 2 candidates, depending on card version
    func parseInitiateSecureChannel(rapdu: APDUResponse) throws -> ([UInt8], [[UInt8]]) {
        
        let data: [UInt8] = rapdu.data
        //logger.info("SATOCHIPLIB: parseInitiateSecureChannel data: \(data.bytesToHex)")
        
        // data= [coordxSize | coordx | sig1Size | sig1 |  sig2Size | sig2]
        var offset: Int = 0
        let coordxSize: Int = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        let coordx = data[offset ..< (offset+coordxSize)]
        offset+=coordxSize
        //logger.info("SATOCHIPLIB: parseInitiateSecureChannel coordx: \(coordx.bytesToHex)")
        
        // msg1 is [coordx_size | coordx]
        let msg1 = data[0 ..< offset]
        let sig1Size = 256*Int(data[offset]) + Int(data[offset+1]);
        offset+=2
        let sig1 = data[offset ..< (offset+sig1Size)]
        offset+=sig1Size
        //logger.info("SATOCHIPLIB: parseInitiateSecureChannel sig1: \(sig1.bytesToHex)")
        
        // recoverPubkey(msg1, sig1, coordx);
        let recoverableSig = try RecoverableSignature(msg: Array(msg1), sig: Array(sig1), coordx: Array(coordx))
        let pubkey: [UInt8] = recoverableSig.publicKey
        //logger.info("SATOCHIPLIB: parseInitiateSecureChannel pubkey: \(pubkey.bytesToHex)")
        
        // recover a list of possible authentikeys from sig2
        // msg2 is [coordxSize | coordx | sig1Size | sig1]
        let msg2 = Array(data[0 ..< offset])
        let sig2Size = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        let sig2 = Array(data[offset ..< (offset+sig2Size)])
        offset+=sig2Size
        
        // get authentikey coordx (this allows to eliminate wrong potential candidates)
        // authentikey coordx is only provided starting with Seedkeeper v0.2 and higher
        var authentikeyCoordx: [UInt8]? = nil
        var authentikeyCoordxSize = 0
        if offset<data.count {
            authentikeyCoordxSize = 256*Int(data[offset]) + Int(data[offset+1])
            offset+=2
            if offset+authentikeyCoordxSize <= data.count{
                authentikeyCoordx = Array(data[offset ..< (offset+authentikeyCoordxSize)])
            }
        }
        
        var authentikeys = [[UInt8]]()
        if let authentikeyCoordx = authentikeyCoordx {
            // recover unique authentikey from msg, sig and coordx
            let recoverableSig = try RecoverableSignature(msg: msg2, sig: sig2, coordx: authentikeyCoordx)
            authentikeys = [recoverableSig.publicKey]
        } else {
            // recover 2 possible authentikeys from msg and sig
            let listRecoverableSig = try ListRecoverableSignature(msg: msg2, sig: sig2)
            authentikeys = listRecoverableSig.pubkeys
        }
        
        return (pubkey, authentikeys)
    }
    
    public func parseBip32GetAuthentikey(rapdu: APDUResponse) throws -> [UInt8] {
        
        // rapdu.checkOK()?
        if rapdu.sw != 0x9000 {
            return [UInt8]()
        }
        
        let data: [UInt8] = rapdu.data
        //logger.info("SATOCHIPLIB: parseBip32GetAuthentikey data: \(data.bytesToHex)")
        
        //data: [coordx_size(2b) | coordx | sig_size(2b) | sig]
        var offset: Int = 0
        //let chaincode: [UInt8] = Array(data[0 ..< 32])
        //offset+=32
        
        // coordx
        let coordxSize: Int = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        let coordx: [UInt8] = Array(data[offset ..< (offset+coordxSize)])
        offset+=coordxSize
        
        // msg1 is [chaincode | coordx_size | coordx]
        let msg1: [UInt8] = Array(data[0 ..< offset])
        
        // sig1
        let sig1Size: Int = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        let sig1: [UInt8] = Array(data[offset ..< (offset+sig1Size)])
        offset+=sig1Size
        
        // pubkey
        let recoverableSig = try RecoverableSignature(msg: msg1, sig: sig1, coordx: coordx)
        let pubkey: [UInt8] = recoverableSig.publicKey
        //logger.info("SATOCHIPLIB: parseBip32GetAuthentikey pubkey: \(pubkey.bytesToHex)")
        
        return pubkey
    }
    
    public func compressPubkey(pubkey: [UInt8]) throws -> [UInt8] {
        if pubkey.count == 33 {
            // already compressed
            return pubkey
        } else if pubkey.count == 65 {
            // in uncompressed form
            var pubkeyComp = Array(pubkey[0..<33])
            // compute compression byte
            let parity = pubkey[64]%2
            if parity == 0 {
                pubkeyComp[0] = UInt8(0x02)
            } else {
                pubkeyComp[0] = UInt8(0x03)
            }
            return pubkeyComp
        } else {
            throw SatocardError.wrongPubkeyLength(length: pubkey.count, expected: 65)
        }
    }
    
    //****************************************
    //*               MARK: BIP32
    //****************************************
    
    public func getBip32PathParentPath(bip32path: String) throws -> String {
        print("In getBip32PathParentPath")
        // todo: sanitize path
        var splitPath = bip32path.components(separatedBy: "/")
        splitPath = Array(splitPath[0..<splitPath.count-1])
        let parentPath = splitPath.joined(separator: "/")
        return parentPath
    }
    
    public func parseBip32PathToBytes(bip32path: String) throws -> (Int, [UInt8]){
        print("In parseBip32PathToBytes")
        // todo: sanitize path
        var splitPath = bip32path.components(separatedBy: "/")
        if splitPath[0] == "m" {
            splitPath = Array(splitPath[1..<splitPath.count])
        }
        
        let depth = splitPath.count
        var bytePath = [UInt8]()
        for index in 0..<depth {
            var subpathString = splitPath[index]
            var subpathInt = UInt32(0)
            // convert string to Int
            if subpathString.hasSuffix("'") || subpathString.hasSuffix("h"){
                subpathString = subpathString.replacingOccurrences(of: "'", with: "")
                subpathString = subpathString.replacingOccurrences(of: "h", with: "")
                guard let tmp = UInt32(subpathString) else {
                    throw ParserError.failedToParseBip32Path(path: bip32path)
                }
                subpathInt = tmp + UInt32(0x80000000)
                
            } else {
                guard let tmp = UInt32(subpathString) else {
                    throw ParserError.failedToParseBip32Path(path: bip32path)
                }
                subpathInt = tmp
            }
            // convert UInt to byte array
            let subPathBytes = subpathInt.toBytes
            bytePath += subPathBytes
        }
        return (depth, bytePath)
    }
    
    public func parseBip32GetExtendedKey(response: [UInt8]) throws -> ([UInt8],[UInt8]) {
        print("In parseBip32GetExtendedKey")
        //todo
//        guard authentikey == nil {
//            throw ParserError.authentikeyNotSet
//        }
            
        // double signature: first is self-signed, second by authentikey
        // firs self-signed sig: data= coordx
        print("[CardDataParser] parseBip32GetExtendedKey: first signature recovery")
        let chaincodeBytes = Array(response[0..<32])
        let dataSize = ((Int(response[32]) & 0x7f)<<8) + (Int(response[33]) & 0xff) // (response[32] & 0x80) is ignored (optimization flag)
        let data = Array(response[34..<(32+2+dataSize)])
        let msgSize = 32+2+dataSize
        let msg = Array(response[0..<msgSize])
        let sigSize = ((Int(response[msgSize]) & 0xff)<<8) + (Int(response[msgSize+1]) & 0xff)
        let signature = Array(response[(msgSize+2)..<(msgSize+2+sigSize)])
        if sigSize==0 {
            throw ParserError.missingSignature
        }
           
        // self-signed
        let coordx = data
        let recoverableSig = try RecoverableSignature(msg: msg, sig: signature, coordx: coordx)
        let pubkeyBytes: [UInt8] = recoverableSig.publicKey
        print("[CardDataParser] parseBip32GetExtendedKey coordx: \(coordx.bytesToHex)")
        print("[CardDataParser] parseBip32GetExtendedKey pubkey: \(pubkeyBytes.bytesToHex)")
        
        // todo
        // second signature by authentikey
//        print("[CardDataParser] parseBip32GetExtendedKey: second signature recovery")
//        let msg2Size = msgSize+2+sigSize
//        let msg2 = Array(response[0..<msg2Size])
//        let sig2Size = ((Int(response[msg2Size]) & 0xff)<<8) + (Int(response[msg2Size+1]) & 0xff)
//        let signature2 = Array(response[(msg2Size+2)..<(msg2Size+2+sig2Size)])
//        let recoverableSig2 = try RecoverableSignature(msg: msg2, sig: signature2, coordx: authentikeyCoordx)
//        let recoveredAuthentikeyBytes = recoverableSig2.publicKey
//        if recoveredAuthentikeyBytes != authentikeyBytes {
//            throw ParserError.failedToRecoverAuthentikey(recovered: recoveredAuthentikeyBytes.bytesToHex, expected: authentikeyBytes)
//        }
//        
        return (pubkeyBytes, chaincodeBytes)
        
    }

    public func parseBip32GetExtendedPrivkey(response: [UInt8]) throws -> ([UInt8], [UInt8]){
        print("In parseBip32GetExtendedPrivkey")
        //todo
//        guard authentikey == nil {
//            throw ParserError.authentikeyNotSet
//        }
            
        // double signature: first is self-signed, second by authentikey
        // firs self-signed sig: data= coordx
        print("[CardDataParser] parseBip32GetExtendedPrivkey: first signature recovery")
        let chaincodeBytes = Array(response[0..<32])
        let dataSize = ((Int(response[32]) & 0x7f)<<8) + (Int(response[33]) & 0xff) // (response[32] & 0x80) is ignored (optimization flag)
        let data = Array(response[34..<(32+2+dataSize)])
        let msgSize = 32+2+dataSize
        let msg = Array(response[0..<msgSize])
        let sigSize = ((Int(response[msgSize]) & 0xff)<<8) + (Int(response[msgSize+1]) & 0xff)
        let signature = Array(response[(msgSize+2)..<(msgSize+2+sigSize)])
        if sigSize==0 {
            throw ParserError.missingSignature
        }
           
        // self-signed
        let privkeyBytes = data
        print("[CardDataParser] parseBip32GetExtendedPrivkey privkey: \(privkeyBytes.bytesToHex)")
        // todo verify sig?
        
        // todo
        // second signature by authentikey
//        print("[CardDataParser] parseBip32GetExtendedKey: second signature recovery")
//        let msg2Size = msgSize+2+sigSize
//        let msg2 = Array(response[0..<msg2Size])
//        let sig2Size = ((Int(response[msg2Size]) & 0xff)<<8) + (Int(response[msg2Size+1]) & 0xff)
//        let signature2 = Array(response[(msg2Size+2)..<(msg2Size+2+sig2Size)])
//        let recoverableSig2 = try RecoverableSignature(msg: msg2, sig: signature2, coordx: authentikeyCoordx)
//        let recoveredAuthentikeyBytes = recoverableSig2.publicKey
//        if recoveredAuthentikeyBytes != authentikeyBytes {
//            throw ParserError.failedToRecoverAuthentikey(recovered: recoveredAuthentikeyBytes.bytesToHex, expected: authentikeyBytes)
//        }
//
        return (privkeyBytes, chaincodeBytes)
    }
    
    public func parseBip32GetExtendedBip85Key(response: [UInt8]) throws -> ([UInt8],[UInt8]) {
        print("In parseBip32GetExtendedBip85Key")
        //todo
//        guard authentikey == nil {
//            throw ParserError.authentikeyNotSet
//        }
            
        // double signature: first is self-signed, second by authentikey
        // firs self-signed sig: data= coordx
        print("[CardDataParser] parseBip32GetExtendedBip85Key: first signature recovery")
        let entropySize = 256*Int(response[0]) + Int(response[1])
        let entropyBytes = Array(response[2..<(2+entropySize)])
        let msgSize = 2 + entropySize
        let msg = Array(response[0..<msgSize])
        let sigSize = ((Int(response[msgSize]) & 0xff)<<8) + (Int(response[msgSize+1]) & 0xff)
        let signature = Array(response[(msgSize+2)..<(msgSize+2+sigSize)])
        if sigSize==0 {
            throw ParserError.missingSignature
        }
        
        // todo
        // second signature by authentikey
//        print("[CardDataParser] parseBip32GetExtendedKey: second signature recovery")
//        let msg2Size = msgSize+2+sigSize
//        let msg2 = Array(response[0..<msg2Size])
//        let sig2Size = ((Int(response[msg2Size]) & 0xff)<<8) + (Int(response[msg2Size+1]) & 0xff)
//        let signature2 = Array(response[(msg2Size+2)..<(msg2Size+2+sig2Size)])
//        let recoverableSig2 = try RecoverableSignature(msg: msg2, sig: signature2, coordx: authentikeyCoordx)
//        let recoveredAuthentikeyBytes = recoverableSig2.publicKey
//        if recoveredAuthentikeyBytes != authentikeyBytes {
//            throw ParserError.failedToRecoverAuthentikey(recovered: recoveredAuthentikeyBytes.bytesToHex, expected: authentikeyBytes)
//        }
//
        return (entropyBytes, [UInt8]())
    }
    
    //****************************************
    //*               MARK: SATODIME
    //****************************************
    
    public func parseSatodimeGetPubkey(rapdu: APDUResponse) throws -> [UInt8] {
        
        //todo: check sw
        if rapdu.sw != 0x9000 {
            return [UInt8]()
        }
        
        let data = rapdu.data
        //logger.info("SATOCHIPLIB: parseSatodimeGetPubkey data: \(data.bytesToHex)")
        //data: [ pubkey_size(2b) | pubkey | sig_size(2b) | sig ]
        var offset = 0
        var dataRemain = data.count
        // pubkeysize
        if dataRemain<2 {
            throw ParserError.parseSatodimeGetPubkeyWrongDataLength(length: dataRemain, expected: 2)
        }
        let pubkeySize = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        dataRemain-=2
        // pubkey
        if dataRemain<pubkeySize {
            throw ParserError.parseSatodimeGetPubkeyWrongDataLength(length: dataRemain, expected: pubkeySize)
        }
        let pubkey: [UInt8] = Array(data[offset ..< (offset+pubkeySize)])
        offset+=pubkeySize
        dataRemain-=pubkeySize
        // msg
        let msg: [UInt8] = Array(data[0 ..< (2+pubkeySize)])
        // sigsize
        if dataRemain<2 {
            throw ParserError.parseSatodimeGetPubkeyWrongDataLength(length: dataRemain, expected: 2)
        }
        let sigSize = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        dataRemain-=2
        //sig
        if dataRemain<sigSize {
            throw ParserError.parseSatodimeGetPubkeyWrongDataLength(length: dataRemain, expected: sigSize)
        }
        let sig: [UInt8] = Array(data[offset ..< (offset+sigSize)])
        offset+=sigSize;
        dataRemain-=sigSize;

        // verify sig
        //logger.info("SATOCHIPLIB: parseSatodimeGetPubkey verifySig: START" );
        //boolean isOk= verifySig(msg, sig, authentikey);
        // TODO!
        //logger.info("SATOCHIPLIB: parseSatodimeGetPubkey verifySig: START" );
        return pubkey
    }
    
    public func parseSatodimeGetPrivkey(rapdu: APDUResponse) throws -> SatodimePrivkeyInfo {
        
        //todo: check sw
        if rapdu.sw != 0x9000 {
            throw ParserError.parseSatodimeGetPrivkeyWrongSw(sw: rapdu.sw)
        }
        
        //data: [ entropy_size(2b) | user_entropy + authentikey_coordx + card_entropy | privkey_size(2b) | privkey | sig_size(2b) | sig ]
        let data = rapdu.data
        //logger.info("SATOCHIPLIB: parseSatodimeGetPrivkey data: \(data.bytesToHex)")
        
        var offset = 0
        var dataRemain = data.count
        if dataRemain<2 {
            throw ParserError.parseSatodimeGetPrivkeyWrongDataLength(length: dataRemain, expected: 2)
        }
        // entropySize
        let entropySize = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        dataRemain-=2
        if entropySize != 96 {
            throw ParserError.parseSatodimeGetPrivkeyWrongDataLength(length: dataRemain, expected: 96)
        }
        if dataRemain<entropySize {
            throw ParserError.parseSatodimeGetPrivkeyWrongDataLength(length: dataRemain, expected: entropySize)
        }
        // entropy
        let entropy: [UInt8] = Array(data[offset ..< (offset+entropySize)])
        offset+=entropySize
        dataRemain-=entropySize
        // privkeySize
        let privkeySize = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        dataRemain-=2
        if dataRemain<privkeySize {
            throw ParserError.parseSatodimeGetPrivkeyWrongDataLength(length: dataRemain, expected: privkeySize)
        }
        // privkey
        let privkey: [UInt8] = Array(data[offset ..< (offset+privkeySize)])
        offset+=privkeySize
        dataRemain-=privkeySize
        // sigsize
        if dataRemain<2 {
            throw ParserError.parseSatodimeGetPrivkeyWrongDataLength(length: dataRemain, expected: 2)
        }
        let sigSize = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        dataRemain-=2
        //sig
        if dataRemain<sigSize {
            throw ParserError.parseSatodimeGetPrivkeyWrongDataLength(length: dataRemain, expected: sigSize)
        }
        let sig: [UInt8] = Array(data[offset ..< (offset+sigSize)])
        offset+=sigSize;
        dataRemain-=sigSize;

        // verify sig
        ////logger.info("SATOCHIPLIB: parseSatodimeGetPrivkey verifySig: START" );
        //boolean isOk= verifySig(msg, sig, authentikey);
        // TODO!
        
        // verify that hash(entropy)==privkey
        // TODO!
        
        return SatodimePrivkeyInfo(privkey: privkey, entropy: entropy)
    }
    
    
    //****************************************
    //*              MARK: PKI PARSER
    //****************************************
    
    public func convertBytesToStringPem(certBytes: [UInt8]) -> String {
        //logger.info("In convertBytesToStringPem")
        let certBase64Raw: String = certBytes.toBase64()
        //logger.info("certBase64Raw: \(certBase64Raw)")
        
        // divide in fixed size chunk
        let chunkSize = 64
        var certBase64: String = "-----BEGIN CERTIFICATE-----\n"
        for offset in stride(from: 0, to: certBase64Raw.count, by: chunkSize){
            certBase64 += certBase64Raw[offset ..< min(offset+chunkSize, certBase64Raw.count)]
            certBase64 += "\n"
        }
        certBase64 += "-----END CERTIFICATE-----\n"
        //logger.info("certBase64: \(certBase64)");
        
        return certBase64
    }
    
    public func convertPemToDer(certPem: String) throws -> SecCertificate {
        // remove header, footer and newlines from pem string
        var parts = certPem.components(separatedBy: "-----BEGIN CERTIFICATE-----")
        var substr = parts[1]
        parts = substr.components(separatedBy: "-----END CERTIFICATE-----")
        substr = parts[0]
        print("Pem cert before: \(substr)")
        substr = substr.replacingOccurrences(of: "\n", with: "")
        print("Pem cert after1: \(substr)")
        guard let certData = Data(base64Encoded: substr) else {
            throw PkiError.failedToDecodeBase64Certificate
        }
        if let certDer = SecCertificateCreateWithData(nil, certData as CFData) {
            print("Der cert: \(certDer)")
            return certDer
        } else {
            throw PkiError.failedToConvertPemCertificate
        }
    }
    
    public func parseVerifyChallengeResponsePerso(rapdu: APDUResponse) throws -> ([UInt8], [UInt8]) {
        
        try rapdu.checkOK()
        // data= [challenge_from_device(32b) | sigSize | sig ]
        let data = rapdu.data
        var offset=0
        var remain = data.count
        // deviceChallenge
        if remain<32 {
            throw ParserError.parseVerifyChallengeResponsePersoWrongDataLength(length: remain, expected: 32)

        }
        let deviceChallenge = Array(data[0 ..< 32])
        offset+=32
        remain-=32
        // sigSize
        if remain<2 {
            throw ParserError.parseVerifyChallengeResponsePersoWrongDataLength(length: remain, expected: 2)
        }
        let sigSize = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        remain-=2
        // sig
        if remain<sigSize {
            throw ParserError.parseVerifyChallengeResponsePersoWrongDataLength(length: remain, expected: sigSize)
        }
        let sig = Array(data[offset ..< (offset+sigSize)])
        return (deviceChallenge, sig)
    }
    
    
    
}
