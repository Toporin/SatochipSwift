import Foundation
import CryptoSwift
import SwiftTLS
//import os.log

public enum SatocardError: Error {
    case pinRequired
    case wrongCardType
}

public enum SatodimeApiError: Error {
    case wrongSlip44Size(length: Int, expected: Int)
    case wrongContractSize(length: Int, expected: Int)
    case wrongTokenidSize(length: Int, expected: Int)
    case wrongDataSize(length: Int, expected: Int)
}

public enum PkiError: Error {
    case emptyCertificate
    case failedToExportPemCertificate
    case failedToDecodeBase64Certificate
    case failedToConvertPemCertificate
//    case failedToParseDevicePemCertificate
//    case rootCaNotFound
//    case subCaNotFound
//    case failedToRecoverPubkeyFromCertificate
//    case failedToVerifyCertificateChain
//    case unsupportedCardType
//    case unsupportedIosVersion
//    case failedToGenerateRandomness
}

public enum PkiReturnCode: Int32 {
    case success
    case unknown
    case emptyCertificate
    case failedToExportPemCertificate
    case failedToParsePemCertificate
    case unsupportedCardType
    case subcaNotFound
    case rootCaNotFound
    case FailedToVerifyDeviceCertificate
    case failedToGenerateRandomness
    case FailedChallengeResponse
}

public enum CardType: String {
    case satochip = "satochip"
    case satodime = "satodime"
    case seedkeeper = "seedkeeper"
    case unknown = "unknown"
    case nocard = "nocard"
}

public class SatocardCommandSet {
    //let //logger = Logger(label: "io.satochip.commandset")
    //private static let logger = Logger(subsystem: "io.satochip.lib", category: "SatocardCommandSet")
    let cardChannel: CardChannel
    let secureChannel: SecureChannel
    let satochipParser: SatocardParser
    public var cardStatus: CardStatus?
    public var satodimeStatus: SatodimeStatus
    public var cardType: CardType
    public var isSecureChannelOpen: Bool { return secureChannel.open }
    
    static let plainInstructionSet: Set = [ISO7816INS.select.rawValue,
                                           SatocardINS.getStatus.rawValue,
                                           SatocardINS.initSecureChannel.rawValue,
                                           SatocardINS.processSecureChannel.rawValue]
    
    public init(cardChannel: CardChannel) {
        self.cardChannel = cardChannel
        self.secureChannel = SecureChannel()
        self.satochipParser = SatocardParser()
        self.cardType = CardType.nocard
        
        self.satodimeStatus = SatodimeStatus()
    }
    
    private var pin0: [UInt8]!
    
    public func select(instanceIdx: UInt8 = 1) throws -> APDUResponse {
        let selectApplet: APDUCommand = APDUCommand(cla: CLA.iso7816.rawValue, ins: ISO7816INS.select.rawValue, p1: 0x04, p2: 0x00, data: SatocardIdentifier.satodimeAID.bytesValue)
        let resp: APDUResponse = try cardChannel.send(selectApplet)

        if resp.sw == StatusWord.ok.rawValue {
            // todo?
            self.cardType = CardType.satodime
        }

        return resp
    }

    func cardTransmit(plainApdu: APDUCommand) throws -> APDUResponse {
        print("in cardTransmit")
        // we try to transmit the APDU until we receive the answer or we receive an unrecoverable error
        var isApduTransmitted: Bool = false
        
        repeat{
            let apduBytes: [UInt8] = plainApdu.serialize()
            print("SATOCHIPLIB: card transmit data: \(apduBytes.bytesToHex)");
            //logger.info("SATOCHIPLIB: card transmit data: \(apduBytes.bytesToHex)");
            
            let ins: UInt8 = apduBytes[1]
            var isEncrypted: Bool = false
            let capdu: APDUCommand
            
            // check if status available
            if cardStatus == nil {
                _ = try self.cardGetStatus(sendEncrypted: false)
            }
            
            // encrypt command if needed
            if cardStatus!.needsSecureChannel && !SatocardCommandSet.plainInstructionSet.contains(ins){
                // open secure channel if needed
                if !secureChannel.open {
                    _ = try cardInitiateSecureChannel()
                }
                // encrypt apdu
                //logger.info("Capdu plaintext: \(plainApdu.toHexString())");
                capdu = secureChannel.encryptSecureChannel(plainApdu: plainApdu)
                //logger.info("Capdu encrypted: \(capdu.toHexString())");
                isEncrypted=true
            } else {
                // plain adpu
                capdu = plainApdu
            }
            
            var rapdu: APDUResponse =  try cardChannel.send(capdu)
            if (rapdu.sw==0x9000){
                if (isEncrypted){
                    //logger.info("Rapdu encrypted: \(rapdu.toHexString())");
                    rapdu = try secureChannel.decryptSecureChannel(encryptedApdu: rapdu)
                    //logger.info("Rapdu decrypted: \(rapdu.toHexString())");
                }
                isApduTransmitted = true // leave loop
                return  rapdu
            }
            // PIN authentication is required
            else if (rapdu.sw==0x9C06){
                _ = try self.cardVerifyPIN(pin: self.pin0)
            }
            // SecureChannel is not initialized
            else if (rapdu.sw==0x9C21){
                secureChannel.reset()
            }
            else {
                // cannot resolve issue at this point
                isApduTransmitted = true; // leave loop
                return rapdu;
            }
        } while(!isApduTransmitted)
    }
    
    // generic
    public func cardGetStatus(sendEncrypted: Bool = true) throws -> APDUResponse {
        //logger.info("in cardGetStatus - info");
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.getStatus.rawValue, p1: 0x00, p2: 0x00, data: [])
        
        //logger.info("SATOCHIPLIB: C-APDU cardGetStatus:  \(capdu.toHexString())");
        let rapdu: APDUResponse
        if sendEncrypted {
            rapdu = try self.cardTransmit(plainApdu: capdu);
        } else {
            rapdu = try cardChannel.send(capdu)
        }
        //logger.info("SATOCHIPLIB: R-APDU cardGetStatus: \(rapdu.toHexString())");
        
        if rapdu.sw == StatusWord.ok.rawValue {
            cardStatus = try CardStatus(rapdu: rapdu)
        }
        
        return rapdu
    }
    
    public func cardDisconnect(){
            secureChannel.reset()
            cardStatus = nil
            pin0 = nil
        cardType = CardType.nocard
        }
    
    public func cardInitiateSecureChannel() throws -> APDUResponse {
        
        let clientPubkey:[UInt8] = secureChannel.generateClientKeypair()
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.initSecureChannel.rawValue, p1: 0x00, p2: 0x00, data: clientPubkey)
        //APDUCommand plainApdu = new APDUCommand(0xB0, INS_INIT_SECURE_CHANNEL, 0x00, 0x00, clientPubkey);
            
        //logger.info("SATOCHIPLIB: CAPDU cardInitiateSecureChannel:  \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU cardInitiateSecureChannel: \(rapdu.toHexString())")
        
        // do something
        let cardPubkey: [UInt8] = try satochipParser.parseInitiateSecureChannel(rapdu: rapdu)
        // setup secure channel
        secureChannel.initiateSecureChannel(cardPubKey: cardPubkey)
        //logger.info("SATOCHIPLIB: secure Channel initiated!")
        
        return rapdu
    }
        
    // only valid for v0.12 and higher
    public func cardGetAuthentikey() throws -> (APDUResponse, [UInt8], String) {
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.exportAuthentikey.rawValue, p1: 0x00, p2: 0x00)
        
        //logger.info("SATOCHIPLIB: CAPDU cardExportAuthentikey: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU cardExportAuthentikey: \(rapdu.toHexString())")
        
        // parse and recover pubkey
        let authentikey = try satochipParser.parseBip32GetAuthentikey(rapdu: rapdu)
        let authentikeyHex = authentikey.bytesToHex
        //logger.info("SATOCHIPLIB: Authentikey from cardExportAuthentikey: \(authentikeyHex)")
        
        return (rapdu, authentikey, authentikeyHex)
    }
    
    //****************************************
    //*             PIN MGMT                 *
    //****************************************
    
    public func cardVerifyPIN(pin: [UInt8]?) throws -> APDUResponse {
        
        var mypin = pin
        if mypin == nil {
            if self.pin0 == nil {
                throw SatocardError.pinRequired
            }
            mypin = self.pin0
        }
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.verifyPin.rawValue, p1: 0x00, p2: 0x00, data: mypin!)
        //logger.info("SATOCHIPLIB: CAPDU cardVerifyPIN: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU cardVerifyPIN: \(rapdu.toHexString())")
        
        do {
            try rapdu.checkAuthOK()
            // update cached pin0 if success
            self.pin0 = mypin
        } catch CardError.wrongPIN(let retryCounter){
            self.pin0 = nil
            //logger.info("SATOCHIPLIB: cardVerifyPIN: wrong pin: retryCounter \(retryCounter)")
            throw CardError.wrongPIN(retryCounter: retryCounter)
        } catch CardError.wrongPINLegacy{
            self.pin0 = nil
            //logger.info("SATOCHIPLIB: cardVerifyPIN: wrong pin (legacy: retryCounter unspecified)")
            throw CardError.wrongPINLegacy
        }
        
        return rapdu
    }
    
    //****************************************
    //*                PKI                   *
    //****************************************
    
    public func cardExportPkiPubkey() throws -> (APDUResponse, [UInt8]) {

        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.exportPkiPubkey.rawValue, p1: 0x00, p2: 0x00)
        
        //logger.info("SATOCHIPLIB: CAPDU cardExportPkiPubkey: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU cardExportPkiPubkey: \(rapdu.toHexString())")
        
        // parse and recover pubkey
        let authentikey = try satochipParser.parseBip32GetAuthentikey(rapdu: rapdu)
        let authentikeyHex = authentikey.bytesToHex
        //logger.info("SATOCHIPLIB: Authentikey from cardExportAuthentikey: \(authentikeyHex)")
        
        return (rapdu, authentikey)
    }
    
    //****************************************
    //*               CARD MGMT              *
    //****************************************
    
    public func cardSetup(pin_tries0: UInt8, pin0: [UInt8]) throws -> APDUResponse {
        
        // use random values for pin1, ublk0, ublk1
        let ublk0 = Crypto.shared.random(count: 8)
        let ublk1 = Crypto.shared.random(count: 8)
        let pin1 = Crypto.shared.random(count: 8)
        
        let ublk_tries0: UInt8 = 0x01
        let ublk_tries1 : UInt8 = 0x01
        let pin_tries1: UInt8 = 0x01
        
        return try self.cardSetup(pinTries0: pin_tries0, ublkTries0: ublk_tries0, pin0: pin0, ublk0: ublk0, pinTries1: pin_tries1, ublkTries1: ublk_tries1, pin1: pin1, ublk1: ublk1);
    }
    
    public func cardSetup(pinTries0: UInt8,
                          ublkTries0: UInt8,
                          pin0: [UInt8],
                          ublk0: [UInt8],
                          pinTries1: UInt8,
                          ublkTries1: UInt8,
                          pin1: [UInt8],
                          ublk1: [UInt8]) throws -> APDUResponse {
        
        // todo: check array size
        
        let pin: [UInt8]=[0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30] //default pin
        
        // data=[pin_length(1) | pin |
        //        pin_tries0(1) | ublk_tries0(1) | pin0_length(1) | pin0 | ublk0_length(1) | ublk0 |
        //        pin_tries1(1) | ublk_tries1(1) | pin1_length(1) | pin1 | ublk1_length(1) | ublk1 |
        //        memsize(2) | memsize2(2) | ACL(3) |
        //        option_flags(2) | hmacsha160_key(20) | amount_limit(8)]
        let optionSize = 0
        //let optionFlags = 0
        
        let dataSize = 16 + pin.count + pin0.count + pin1.count + ublk0.count + ublk1.count + optionSize
//        let data: [UInt8] = [pin.count] + pin +
//                            [pinTries0, ublkTries0] +
//                            [pin0.count] + pin0 +
//                            [ublk0.count] + ublk0 +
//                            [pinTries1, ublkTries1] +
//                            [pin1.count] + pin1 +
//                            [ublk1.count] + ublk1 +
//                            [0, 32, 0, 32] // memsize default (deprecated)
//                            [0x01, 0x01, 0x01]// ACL (deprecated)
        
        let data1: [UInt8] =    [UInt8(pin.count)] + pin
        let data2: [UInt8] =    [pinTries0, ublkTries0] +
                                [UInt8(pin0.count)] + pin0 +
                                [UInt8(ublk0.count)] + ublk0
        let data3: [UInt8] =    [pinTries1, ublkTries1] +
                                [UInt8(pin1.count)] + pin1 +
                                [UInt8(ublk1.count)] + ublk1
        let data4: [UInt8] =    [0x00, 32, 0x00, 32] +// memsize default (deprecated)
                                [0x01, 0x01, 0x01]// ACL (deprecated)
        let data: [UInt8] =  data1 + data2 + data3 + data4
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.setup.rawValue, p1: 0x00, p2: 0x00, data: data)
        //logger.info("SATOCHIPLIB: CAPDU cardSetup: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU cardSetup: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        self.pin0 = pin0
        if (self.cardType == CardType.satodime ){ // cache values
            try satodimeStatus.updateStatusFromSetup(rapdu: rapdu)
        }
        
        return rapdu
    }
    
    public func satodimeCardSetup() throws -> APDUResponse {
        
        guard (self.cardType == CardType.satodime ) else {
            throw SatocardError.wrongCardType
        }
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.setup.rawValue, p1: 0x00, p2: 0x00, data: [])
        //logger.info("SATOCHIPLIB: CAPDU satodimeCardSetup: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeCardSetup: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        // satodime cardSetup returns a secret unlockCode that is required to perform sensitive actions on the card (seal, unseal, reset, transfer card)
        try satodimeStatus.updateStatusFromSetup(rapdu: rapdu)
        
        return rapdu
    }
    
    
    //****************************************
    //*               SATOCHIP               *
    //****************************************
    
    // Todo!
    
    //****************************************
    //*               SATODIME               *
    //****************************************
    
    public func satodimeGetStatus() throws -> APDUResponse {
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.getSatodimeStatus.rawValue, p1: 0x00, p2: 0x00)
        
        //logger.info("SATOCHIPLIB: CAPDU satodimeGetStatus: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeGetStatus: \(rapdu.toHexString())")
        
        self.satodimeStatus = try SatodimeStatus(rapdu: rapdu)
        
        //return (rapdu, satodimeStatus)
        return rapdu
    }
    
    public func satodimeGetKeyslotStatus(keyNbr: UInt8) throws -> APDUResponse {
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.getSatodimeKeyslotStatus.rawValue, p1: keyNbr, p2: 0x00)
        //logger.info("SATOCHIPLIB: CAPDU satodimeGetKeyslotStatus: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeGetKeyslotStatus: \(rapdu.toHexString())")
        
        // todo: parse response?
        
        return rapdu
    }
    
    public func satodimeSetKeyslotStatusPart0(keyNbr: UInt8, RFU1: UInt8, RFU2: UInt8, keyAsset: UInt8, keySlip44: UInt32, keyContract: [UInt8], keyTokenid: [UInt8]) throws -> APDUResponse {
        let slip44Bytes = keySlip44.toBytes
        return try self.satodimeSetKeyslotStatusPart0(keyNbr: keyNbr, RFU1: RFU1, RFU2: RFU2, keyAsset: keyAsset, keySlip44: slip44Bytes, contractBytes: keyContract, tokenidBytes: keyTokenid)
    }
    
    public func satodimeSetKeyslotStatusPart0(keyNbr: UInt8, RFU1: UInt8, RFU2: UInt8, keyAsset: UInt8, keySlip44: [UInt8], contractBytes: [UInt8], tokenidBytes: [UInt8]) throws -> APDUResponse {
        
        // check inputs
        if keySlip44.count != SatocardCst.sizeSlip44 {
            throw SatodimeApiError.wrongSlip44Size(length: keySlip44.count, expected: SatocardCst.sizeSlip44)
        }
        
        // sanitize bytes arrays for contracts and tokenid
        var contractBytes = contractBytes
        let contractSize = contractBytes.count
        if contractSize > 32 {//SatochipCst.sizeContract
            throw SatodimeApiError.wrongContractSize(length: contractBytes.count, expected: SatocardCst.sizeContract)
        } else {
            // padd with 0
            contractBytes = [UInt8(0), UInt8(contractSize&0xFF)] + contractBytes + [UInt8](repeating: 0, count: 32 - contractSize)
        }
        
        var tokenidBytes = tokenidBytes
        let tokenidSize = tokenidBytes.count
        if tokenidSize > 32 {//SatochipCst.sizeContract
            throw SatodimeApiError.wrongContractSize(length: contractBytes.count, expected: SatocardCst.sizeContract)
        } else {
            // padd with 0
            tokenidBytes = [UInt8(0), UInt8(tokenidSize&0xFF)] + tokenidBytes + [UInt8](repeating: 0, count: 32 - tokenidSize)
        }
        
        // compute unlock code
        let sizeData: UInt8 = UInt8(SatocardCst.sizeUnlockCounter + SatocardCst.sizeUnlockCode + 3 + SatocardCst.sizeSlip44 + SatocardCst.sizeContract + SatocardCst.sizeTokenid)
        let challenge: [UInt8] = [CLA.proprietary.rawValue,
                                  SatocardINS.setSatodimeKeyslotStatus.rawValue,
                                  keyNbr,
                                  0x00,
                                  sizeData]
        let unlockCode: [UInt8] = satodimeStatus.computeUnlockCode(challenge: challenge)
        let data: [UInt8] = unlockCode + [RFU1, RFU2, keyAsset] + keySlip44 + contractBytes + tokenidBytes
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.setSatodimeKeyslotStatus.rawValue, p1: keyNbr, p2: 0x00, data: data)
        //logger.info("SATOCHIPLIB: CAPDU satodimeSetKeyslotStatusPart0: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeSetKeyslotStatusPart0: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        satodimeStatus.incrementUnlockCounter()

        return rapdu
    }
    
    public func satodimeSetKeyslotStatusPart1(keyNbr: UInt8, keyData: [UInt8]) throws -> APDUResponse {
        
        // check inputs
        if keyData.count != SatocardCst.sizeData {
            throw SatodimeApiError.wrongDataSize(length: keyData.count, expected: SatocardCst.sizeData)
        }
            
        // compute unlock code
        let sizeData: UInt8 = UInt8(SatocardCst.sizeUnlockCounter + SatocardCst.sizeUnlockCode +     SatocardCst.sizeData)
        let challenge: [UInt8] = [CLA.proprietary.rawValue,
                                  SatocardINS.setSatodimeKeyslotStatus.rawValue,
                                  keyNbr,
                                  0x01,
                                  sizeData]
        let unlockCode: [UInt8] = satodimeStatus.computeUnlockCode(challenge: challenge)
        let data: [UInt8] = unlockCode + keyData
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.setSatodimeKeyslotStatus.rawValue, p1: keyNbr, p2: 0x01, data: data)
        //logger.info("SATOCHIPLIB: CAPDU satodimeSetKeyslotStatusPart1: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeSetKeyslotStatusPart1: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        satodimeStatus.incrementUnlockCounter()
        
        return rapdu
    }
    
    public func satodimeGetPubkey(keyNbr: UInt8) throws -> APDUResponse {
    
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.getSatodimePubkey.rawValue, p1: keyNbr, p2: 0x00)
        //logger.info("SATOCHIPLIB: CAPDU satodimeGetPubkey: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeGetPubkey: \(rapdu.toHexString())")
        
        return rapdu
    }
    
    public func satodimeGetPrivkey(keyNbr: UInt8) throws -> APDUResponse {
           
        // compute unlock code
        let sizeData: UInt8 = UInt8(SatocardCst.sizeUnlockCounter + SatocardCst.sizeUnlockCode)
        let challenge: [UInt8] = [CLA.proprietary.rawValue,
                                  SatocardINS.getSatodimePrivkey.rawValue,
                                  keyNbr,
                                  0x00,
                                  sizeData]
        let unlockCode: [UInt8] = satodimeStatus.computeUnlockCode(challenge: challenge)
        let data: [UInt8] = unlockCode
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.getSatodimePrivkey.rawValue, p1: keyNbr, p2: 0x00, data: data)
        //logger.info("SATOCHIPLIB: CAPDU satodimeGetPrivkey: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeGetPrivkey: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        satodimeStatus.incrementUnlockCounter()
        
        return rapdu
    }
    
    public func satodimeSealKey(keyNbr: UInt8, entropyUser: [UInt8]) throws -> APDUResponse {
        
        // pad entropy to 32 bytes
        var entropyUser = entropyUser
        if entropyUser.count < 32 {
            entropyUser = entropyUser + [UInt8](repeating: 0, count: 32-entropyUser.count)
        }
        
        // compute unlock code
        let sizeData: UInt8 = UInt8(SatocardCst.sizeUnlockCounter + SatocardCst.sizeUnlockCode + SatocardCst.sizeEntropy)
        let challenge: [UInt8] = [CLA.proprietary.rawValue,
                                  SatocardINS.sealSatodimeKey.rawValue,
                                  keyNbr,
                                  0x00,
                                  sizeData]
        let unlockCode: [UInt8] = satodimeStatus.computeUnlockCode(challenge: challenge)
        let data: [UInt8] = unlockCode + entropyUser
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.sealSatodimeKey.rawValue, p1: keyNbr, p2: 0x00, data: data)
        //logger.info("SATOCHIPLIB: CAPDU satodimeSealKey: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeSealKey: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        satodimeStatus.incrementUnlockCounter()
        
        return rapdu
    }
    
    public func satodimeUnsealKey(keyNbr: UInt8) throws -> APDUResponse {
           
        // compute unlock code
        let sizeData: UInt8 = UInt8(SatocardCst.sizeUnlockCounter + SatocardCst.sizeUnlockCode)
        let challenge: [UInt8] = [CLA.proprietary.rawValue,
                                  SatocardINS.unsealSatodimeKey.rawValue,
                                  keyNbr,
                                  0x00,
                                  sizeData]
        let unlockCode: [UInt8] = satodimeStatus.computeUnlockCode(challenge: challenge)
        let data: [UInt8] = unlockCode
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.unsealSatodimeKey.rawValue, p1: keyNbr, p2: 0x00, data: data)
        //logger.info("SATOCHIPLIB: CAPDU satodimeUnsealKey: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeUnsealKey: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        satodimeStatus.incrementUnlockCounter()
        
        return rapdu
    }
    
    public func satodimeResetKey(keyNbr: UInt8) throws -> APDUResponse {
           
        // compute unlock code
        let sizeData: UInt8 = UInt8(SatocardCst.sizeUnlockCounter + SatocardCst.sizeUnlockCode)
        let challenge: [UInt8] = [CLA.proprietary.rawValue,
                                  SatocardINS.resetSatodimeKey.rawValue,
                                  keyNbr,
                                  0x00,
                                  sizeData]
        let unlockCode: [UInt8] = satodimeStatus.computeUnlockCode(challenge: challenge)
        let data: [UInt8] = unlockCode
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.resetSatodimeKey.rawValue, p1: keyNbr, p2: 0x00, data: data)
        //logger.info("SATOCHIPLIB: CAPDU satodimeResetKey: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeResetKey: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        satodimeStatus.incrementUnlockCounter()
        
        return rapdu
    }
    
    public func satodimeInitiateOwnershipTransfer() throws -> APDUResponse {
           
        // compute unlock code
        let sizeData: UInt8 = UInt8(SatocardCst.sizeUnlockCounter + SatocardCst.sizeUnlockCode)
        let challenge: [UInt8] = [CLA.proprietary.rawValue,
                                  SatocardINS.initiateSatodimeTransfer.rawValue,
                                  0x00,
                                  0x00,
                                  sizeData]
        let unlockCode: [UInt8] = satodimeStatus.computeUnlockCode(challenge: challenge)
        let data: [UInt8] = unlockCode
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.initiateSatodimeTransfer.rawValue, p1: 0x00, p2: 0x00, data: data)
        //logger.info("SATOCHIPLIB: CAPDU satodimeInitiateOwnershipTransfer: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeInitiateOwnershipTransfer: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        satodimeStatus.incrementUnlockCounter()
        
        return rapdu
    }
    
    //****************************************
    //*            PKI commands              *
    //****************************************
        
    public func cardExportPersoPubkey() throws -> APDUResponse {
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.exportPkiPubkey.rawValue, p1: 0x00, p2: 0x00)
        //logger.info("SATOCHIPLIB: CAPDU cardExportPersoPubkey: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU cardExportPersoPubkey: \(rapdu.toHexString())")
        
        return rapdu
    }
    
    public func cardExportPersoCertificate() throws -> ([UInt8], String) {
            
        // init
        let p1: UInt8 = 0x00
        var p2: UInt8 = 0x01 // init
        
        var capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.exportPkiCertificate.rawValue, p1: p1, p2: p2)
        //logger.info("SATOCHIPLIB: CAPDU cardExportPersoCertificate: \(capdu.toHexString())")
        var rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU cardExportPersoCertificate: \(rapdu.toHexString())")
        
        _ = try rapdu.checkOK()
        var response: [UInt8] = rapdu.data
        let certificateSize = Int(response[0] & 0xFF)*256 + Int(response[1] & 0xFF)
        if certificateSize==0 {
            //return ([UInt8](), "");
            // todo: throw a specific error?
            throw PkiError.emptyCertificate
        }
            
        // UPDATE apdu: certificate data in chunks
        p2 = 0x02 //update
        var certBytes: [UInt8] = [UInt8]()
        let chunkSize = 128
        //var chunk: [UInt8]
        var certRemaining = certificateSize
        var certOffset = 0
        var data = [UInt8](repeating: 0, count: 4)
        while certRemaining>128 {
            // data=[ chunk_offset(2b) | chunk_size(2b) ]
            data[0] = UInt8((certOffset>>8)&0xFF)
            data[1] = UInt8(certOffset&0xFF)
            data[2] = UInt8((chunkSize>>8)&0xFF)
            data[3] = UInt8(chunkSize & 0xFF)
            
            capdu = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.exportPkiCertificate.rawValue, p1: p1, p2: p2, data: data)
            //logger.info("SATOCHIPLIB: CAPDU cardExportPersoCertificate update: \(capdu.toHexString())")
            rapdu = try self.cardTransmit(plainApdu: capdu)
            //logger.info("SATOCHIPLIB: RAPDU cardExportPersoCertificate update: \(rapdu.toHexString())")
            
            // update certificate
            response = rapdu.data
            certBytes += Array(response[0 ..< chunkSize])
            certRemaining-=chunkSize
            certOffset+=chunkSize
        }
            
        // last chunk
        data[0] = UInt8((certOffset>>8)&0xFF)
        data[1] = UInt8(certOffset&0xFF)
        data[2] = UInt8((certRemaining>>8)&0xFF)
        data[3] = UInt8(certRemaining & 0xFF)
        capdu = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.exportPkiCertificate.rawValue, p1: p1, p2: p2, data: data)
        //logger.info("SATOCHIPLIB: CAPDU cardExportPersoCertificate final: \(capdu.toHexString())")
        rapdu = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU cardExportPersoCertificate final: \(rapdu.toHexString())")
        // update certificate
        response = rapdu.data
        certBytes += Array(response[0 ..< certRemaining])
        
        // parse and return raw certificate
        let certPem: String = satochipParser.convertBytesToStringPem(certBytes: certBytes)
            
        return (certBytes, certPem)
    }
    
    public func cardChallengeResponsePerso(challengeFromHost: [UInt8]) throws -> APDUResponse {
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.challengeResponsePki.rawValue, p1: 0x00, p2: 0x00, data: challengeFromHost)
        //logger.info("SATOCHIPLIB: CAPDU cardChallengeResponsePerso: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU cardChallengeResponsePerso: \(rapdu.toHexString())")
        
        return rapdu
    }
    
    public func cardVerifyAuthenticity() throws -> (PkiReturnCode, [String:String]) {
        //logger.info("In cardVerifyAuthenticity")
        var errorCode = PkiReturnCode.unknown
        var deviceTxt = ""
        var subcaTxt = ""
        var caTxt = ""
        var dic = [String:String]()
//        dic["subcaPem"] = ""
//        dic["caPem"] = ""
//        dic["devicePem"] = ""
        
        // get certificate from device
        let certBytes: [UInt8]
        let devicePem: String
        do {
            (certBytes, devicePem) = try cardExportPersoCertificate()
        } catch PkiError.emptyCertificate {
            return (PkiReturnCode.emptyCertificate, dic)
        } catch PkiError.failedToExportPemCertificate {
            return (PkiReturnCode.failedToExportPemCertificate, dic)
        }
        //logger.info("Device PEM: \(devicePem)")
        guard let deviceCertificate = SwiftTLS.X509.Certificate(PEMString: devicePem) else {
            //throw PkiError.failedToParseDevicePemCertificate
            return (PkiReturnCode.failedToParsePemCertificate, dic)
        }
        print("certificate: \(deviceCertificate)")
        let tbsData = deviceCertificate.tbsCertificate.DEREncodedCertificate! // <=
        print("tbsData: type:\(type(of: tbsData)) value: \(tbsData)")
        let subjectPublicKeyInfo = deviceCertificate.tbsCertificate.subjectPublicKeyInfo
        print("subjectPublicKeyInfo: type:\(type(of: subjectPublicKeyInfo)) value: \(subjectPublicKeyInfo)")
        let subjectPublicKey = subjectPublicKeyInfo.subjectPublicKey
        print("subjectPublicKeyInfo: type:\(type(of: subjectPublicKey)) value: \(subjectPublicKey)")
        let devicePubkeyBytes = subjectPublicKey.bits // <=
        print("pubkeyBytes: type:\(type(of: devicePubkeyBytes)) value: \(devicePubkeyBytes)")
        let algorithm = subjectPublicKeyInfo.algorithm
        print("algorithm: type:\(type(of: algorithm)) value: \(algorithm)")
        let signatureValue = deviceCertificate.signatureValue
        print("signatureValue: type:\(type(of: signatureValue)) value: \(signatureValue)")
        let signatureBytes = signatureValue.bits // <=
        print("signatureBytes: type:\(type(of: signatureBytes)) value: \(signatureBytes)")
        let signatureAlgorithm = deviceCertificate.signatureAlgorithm
        print("signatureValue: type:\(type(of: signatureAlgorithm)) value: \(signatureAlgorithm)")
        
        deviceTxt += "Device Certificate: \n\n"
        deviceTxt += "Pubkey: " + devicePubkeyBytes.bytesToHex + "\n"
        deviceTxt += "Signature: " + signatureBytes.bytesToHex + "\n"
        deviceTxt += "PEM: \n" + devicePem + "\n"
        dic["devicePubkey"] = devicePubkeyBytes.bytesToHex
        dic["deviceSig"] = signatureBytes.bytesToHex
        dic["devicePem"] = devicePem
        
        // load subca certificate
        let subcaPem: String
        switch self.cardType {
        case CardType.satodime:
            subcaPem = PkiCertificates.satodimeCertPem
        case CardType.satochip:
            subcaPem = PkiCertificates.satochipCertPem
        case CardType.seedkeeper:
            subcaPem = PkiCertificates.seedkeeperCertPem
        default:
            //throw PkiError.unsupportedCardType
            return (PkiReturnCode.unsupportedCardType, dic)
        }
        print("subcaPem: \(subcaPem)")
        guard let subcaCertificate = SwiftTLS.X509.Certificate(PEMString: subcaPem) else {
            //throw PkiError.subCaNotFound
            return (PkiReturnCode.subcaNotFound, dic)
        }
        print("subcaCertificate: \(subcaCertificate)")
        let subcaTbsData = subcaCertificate.tbsCertificate.DEREncodedCertificate!
        print("subcaTbsData: type:\(type(of: subcaTbsData)) value: \(subcaTbsData)")
        let subcaSubjectPublicKeyInfo = subcaCertificate.tbsCertificate.subjectPublicKeyInfo
        print("subjectPublicKeyInfo: type:\(type(of: subcaSubjectPublicKeyInfo)) value: \(subcaSubjectPublicKeyInfo)")
        let subcaSubjectPublicKey = subcaSubjectPublicKeyInfo.subjectPublicKey
        print("subcaSubjectPublicKey: type:\(type(of: subcaSubjectPublicKey)) value: \(subcaSubjectPublicKey)")
        let subcaPubkeyBytes = subcaSubjectPublicKey.bits // <=
        print("subcaPubkeyBytes: type:\(type(of: subcaPubkeyBytes)) value: \(subcaPubkeyBytes)")
        subcaTxt += "Subca Certificate: \n\n"
        subcaTxt += "Pubkey: " + subcaPubkeyBytes.bytesToHex + "\n"
        subcaTxt += "PEM: \n" + subcaPem + "\n"
        dic["subcaPubkey"] = subcaPubkeyBytes.bytesToHex
        dic["subcaPem"] = subcaPem
        
        //verify sig using SwiftTLS.ECDSA.verify (Slow!)
//        guard let subcaEcdsa = ECDSA(publicKeyInfo: subcaSubjectPublicKeyInfo) else {
//            throw PkiError.rootCaNotFound
//        }
//        let verified2 = subcaEcdsa.verify(signature: certificate.signatureValue.bits, data: ecdsa.hashAlgorithm.hashFunction(tbsData))
        
        // verify sig using libsec256k1
        let msgHash = Crypto.shared.sha256(tbsData)
        let verifyCert = Crypto.shared.secp256k1Verify(sigBytes: deviceCertificate.signatureValue.bits, msgHash: msgHash, pubkeyBytes: subcaPubkeyBytes)
        print("verifyCert: \(verifyCert)")
        if (verifyCert != 1){
            return (PkiReturnCode.FailedToVerifyDeviceCertificate, dic)
        }
        // now using wrong hash, should return 0 (fail):
//        let msgHashWrong = [UInt8](repeating: 0, count: 32)
//        let verifyCertWrong = Crypto.shared.secp256k1Verify(sigBytes: deviceCertificate.signatureValue.bits, msgHash: msgHashWrong, pubkeyBytes: subcaPubkeyBytes)
//        print("verifyCertWrong: \(verifyCertWrong)")
        
        // perform challenge-response with the card to ensure that the key is correctly loaded in the device
        let randCount = 32
        var randBytes = [UInt8](repeating: 0, count: randCount)
        let randStatus = SecRandomCopyBytes(
            kSecRandomDefault,
            randCount,
            &randBytes
        )
        // A status of errSecSuccess indicates success
        guard randStatus == errSecSuccess else {
            //throw PkiError.failedToGenerateRandomness
            return(PkiReturnCode.failedToGenerateRandomness, dic)
        }
        let rapduChalresp = try cardChallengeResponsePerso(challengeFromHost: randBytes)
        let (deviceChallenge, sig) = try satochipParser.parseVerifyChallengeResponsePerso(rapdu: rapduChalresp)
        let fullChallenge = "Challenge:".utf8 + deviceChallenge + randBytes
        // verify signature is correct
        let challengeHash = Crypto.shared.sha256(fullChallenge)
        let verifyChallenge = Crypto.shared.secp256k1Verify(sigBytes: sig, msgHash: challengeHash, pubkeyBytes: devicePubkeyBytes)
        print("verifyChallenge: \(verifyChallenge)")
        if (verifyChallenge != 1){
            return (PkiReturnCode.FailedChallengeResponse, dic)
        }
        
        // success!
        return (PkiReturnCode.success, dic)
    }
    
    //****************************************
    //*               SEEDKEEPER             *
    //****************************************
    
    
}

