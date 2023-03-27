import Foundation
import CryptoSwift
//import Logging

public enum ParserError: Error {
    case parseSatodimeGetPubkeyWrongDataLength(length: Int, expected: Int)
    case parseSatodimeGetPrivkeyWrongDataLength(length: Int, expected: Int)
    case parseSatodimeGetPrivkeyWrongSw(sw: UInt16)
    case parseVerifyChallengeResponsePersoWrongDataLength(length: Int, expected: Int)
}

public class SatocardParser {
    //let //logger = Logger(label: "io.satochip.parser")
    
    public init() {}
    
    func parseInitiateSecureChannel(rapdu: APDUResponse) throws -> [UInt8] {
        
        let data: [UInt8] = rapdu.data
        //logger.info("SATOCHIPLIB: parseInitiateSecureChannel data: \(data.bytesToHex)")

        // data= [coordxSize | coordx | sig1Size | sig1 |  sig2Size | sig2]
        var offset: Int = 0
        let coordxSize: Int = 256*Int(data[offset]) + Int(data[offset+1])
        offset+=2
        //var coordx:[UInt8] = [UInt8](repeating: 0, count: coordxSize)
        let coordx = data[offset ..< (offset+coordxSize)]
        //System.arraycopy(data, offset, coordx, 0, coordxSize);
        offset+=coordxSize
        //logger.info("SATOCHIPLIB: parseInitiateSecureChannel coordx: \(coordx.bytesToHex)")
        
        // msg1 is [coordx_size | coordx]
        //byte[] msg1= new byte[2+coordxSize];
        //System.arraycopy(data, 0, msg1, 0, msg1.length);
        let msg1 = data[0 ..< offset]
        // int sig1Size= 256*data[offset++] + data[offset++];
        let sig1Size = 256*Int(data[offset]) + Int(data[offset+1]);
        offset+=2
        //byte[] sig1= new byte[sig1Size];
        //System.arraycopy(data, offset, sig1, 0, sig1Size);
        let sig1 = data[offset ..< (offset+sig1Size)]
        offset+=sig1Size
        //logger.info("SATOCHIPLIB: parseInitiateSecureChannel sig1: \(sig1.bytesToHex)")
        
        // msg2 is [coordxSize | coordx | sig1Size | sig1]
        //byte[] msg2= new byte[2+coordxSize + 2 + sig1Size];
        //System.arraycopy(data, 0, msg2, 0, msg2.length);
        let msg2 = data[0 ..< offset]
        //int sig2Size= 256*data[offset++] + data[offset++];
        let sig2Size = 256*Int(data[offset]) + Int(data[offset+1]);
        offset+=2
        //byte[] sig2= new byte[sig2Size];
        //System.arraycopy(data, offset, sig2, 0, sig2Size);
        let sig2 = data[offset ..< (offset+sig2Size)]
        offset+=sig2Size
        
        // recoverPubkey(msg1, sig1, coordx);
        let recoverableSig = try RecoverableSignature(msg: Array(msg1), sig: Array(sig1), coordx: Array(coordx))
        let pubkey: [UInt8] = recoverableSig.publicKey
        //logger.info("SATOCHIPLIB: parseInitiateSecureChannel pubkey: \(pubkey.bytesToHex)")
        
        // todo: recover from sig2
        return pubkey;
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
    
    //****************************************
    //*               SATODIME               *
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
    //*              PKI PARSER              *
    //****************************************
    
    public func convertBytesToStringPem(certBytes: [UInt8]) -> String {
        //logger.info("In convertBytesToStringPem")
        let certBase64Raw: String = certBytes.toBase64()!
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
