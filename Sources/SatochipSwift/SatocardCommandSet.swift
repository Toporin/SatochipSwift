import Foundation
import CryptoSwift
import SwiftTLS
//import OSLog
//import os.log

public enum SatocardError: Error {
    case pinRequired
    case wrongCardType
    case wrongResponseLength(length: Int, expected: Int)
    case wrongParameter(msg: String)
    case unsupportedFeature(msg: String)
    case uninitializedCard(msg: String)
    
    case pathTooLongForBip32Derivation(length: Int, expected: Int)
    case unexpectedErrorDuringBip32Derivation(sw: Int)
    case unsupportedLegacyOptionDuringBip32Derivation
    case wrongPubkeyLength(length: Int, expected: Int)
    case wrongXpubLength(length: Int, expected: Int)
}

public enum SatodimeApiError: Error {
    case wrongSlip44Size(length: Int, expected: Int)
    case wrongContractSize(length: Int, expected: Int)
    case wrongTokenidSize(length: Int, expected: Int)
    case wrongDataSize(length: Int, expected: Int)
}

public enum SeedkeeperApiError: Error {
    case wrongSecretSize(size: Int)
    
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
    case anycard = "anycard"
    
    public var aidBytesValue: [UInt8] {
        switch self {
        case .satochip:
            return SatocardIdentifier.satochipAID.bytesValue
        case .satodime:
            return SatocardIdentifier.satodimeAID.bytesValue
        case .seedkeeper:
            return SatocardIdentifier.seedkeeperAID.bytesValue
        case .nocard:
            return [UInt8]()
        case .unknown:
            return [UInt8]()
        case .anycard:
            return [UInt8]()
        }
    }
}

public class SatocardCommandSet {
    //let //logger = Logger(label: "io.satochip.commandset")
    //let logger = Logger(subsystem: "io.satochip.lib", category: "SatocardCommandSet")
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
    
    static let sensitiveInstructionSet: Set = [SatocardINS.bip32ImportSeed.rawValue,
                                               SatocardINS.changePin.rawValue,
                                               SatocardINS.verifyPin.rawValue,
                                               SatocardINS.unblockPin.rawValue,
                                               SatocardINS.getSatodimePrivkey.rawValue,
                                               SatocardINS.importSecret.rawValue,
                                               SatocardINS.exportSecret.rawValue,
                                               SatocardINS.set2FaKey.rawValue]
    
    public init(cardChannel: CardChannel) {
        self.cardChannel = cardChannel
        self.secureChannel = SecureChannel()
        self.satochipParser = SatocardParser()
        self.cardType = CardType.nocard
        
        self.satodimeStatus = SatodimeStatus()
    }
    
    private var pin0: [UInt8]!
    
    // legacy
    public func select() throws -> APDUResponse {
        let selectApplet = APDUCommand(cla: CLA.iso7816.rawValue,
                                      ins: ISO7816INS.select.rawValue,
                                      p1: 0x04,
                                      p2: 0x00,
                                      data: SatocardIdentifier.satodimeAID.bytesValue)
        let resp: APDUResponse = try cardChannel.send(selectApplet)
        if resp.sw == StatusWord.ok.rawValue {
            // todo?
            self.cardType = CardType.seedkeeper
        }
        return resp
    }
    
    public func selectApplet(cardType: CardType = CardType.anycard) throws -> (APDUResponse, CardType) {
        
        if cardType == CardType.nocard || cardType == CardType.unknown {
            throw SatocardError.wrongCardType
        }
        
        if cardType == CardType.anycard {
            for card in [CardType.satodime, CardType.seedkeeper, CardType.satochip] {
                do {
                    var (rapdu, foundCardType) = try selectApplet(cardType: card)
                    return (rapdu, foundCardType)
                } catch let error {
                    print(error.localizedDescription)
                }
            }
        }
        
        let selectApplet = APDUCommand(cla: CLA.iso7816.rawValue,
                                        ins: ISO7816INS.select.rawValue,
                                        p1: 0x04,
                                        p2: 0x00,
                                       data: cardType.aidBytesValue)
        let rapdu: APDUResponse = try cardChannel.send(selectApplet)
        if rapdu.sw == StatusWord.ok.rawValue {
            // todo?
            self.cardType = cardType
        } else {
            throw SatocardError.wrongCardType
        }
        return (rapdu, cardType)
    }
    

    func cardTransmit(plainApdu: APDUCommand) throws -> APDUResponse {
        print("in cardTransmit")
        // we try to transmit the APDU until we receive the answer or we receive an unrecoverable error
        var isApduTransmitted: Bool = false
        
        repeat{
            let apduBytes: [UInt8] = plainApdu.serialize()
            
            let ins: UInt8 = apduBytes[1]
            // for debug purpose
            if !SatocardCommandSet.sensitiveInstructionSet.contains(ins){
                print("SATOCHIPLIB: card transmit data: \(apduBytes.bytesToHex)");
                //logger.info("SATOCHIPLIB: card transmit data: \(apduBytes.bytesToHex)");
            } else {
                print("SATOCHIPLIB: card transmit data: \(apduBytes[0..<5].bytesToHex)\(String(repeating: "*", count: (apduBytes.count-5)))");
            }
            
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
    
    public func cardDisconnect(){
        secureChannel.reset()
        cardStatus = nil
        pin0 = nil
        cardType = CardType.nocard
    }
    
    //****************************************
    //*         MARK: COMMON COMMANDS        *
    //****************************************
    
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
        
    // only valid for Satochip v0.12 and higher
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
    
    public func cardGetLabel() throws -> String {
        print("In cardGetLabel")
        let cla: UInt8 = CLA.proprietary.rawValue
        let ins: UInt8 = SatocardINS.cardLabel.rawValue
        let p1: UInt8 = 0x00
        let p2: UInt8 = 0x01 // get
        
        let command = APDUCommand(cla: cla, ins: ins, p1: p1, p2: p2, data: [])
        
        let response = try self.cardTransmit(plainApdu: command)
        
        var label: String
        
        if response.sw1 == 0x90 && response.sw2 == 0x00 {
            let labelSize = response.data[0] //response[0]
            do {
                if let labelData = String(data: Data(response.data[1...]), encoding: .utf8) {
                    label = labelData
                } else {
                    throw NSError(domain: "UnicodeDecodeError", code: 0, userInfo: nil)
                }
            } catch {
                NSLog("UnicodeDecodeError while decoding card label !")
                label = String(bytes: response.data[1...], encoding: .utf8) ?? "\(response.data[1...])"
            }
        } else if response.sw1 == 0x6d && response.sw2 == 0x00 {
            label = "(none)"
        } else {
            NSLog("Error while recovering card label: \(response.sw1) \(response.sw2)")
            label = "(unknown)"
        }
        
        // return (response, sw1, sw2, label)
        return label
    }
    
    public func cardSetLabel(label: String) throws -> Bool {
        NSLog("In cardSetLabel")
        let cla: UInt8 = CLA.proprietary.rawValue
        let ins: UInt8 = SatocardINS.cardLabel.rawValue
        let p1: UInt8 = 0x00
        let p2: UInt8 = 0x00 // set
        
        guard let labelData = label.data(using: .utf8) else {
            throw NSError(domain: "EncodingError", code: 0, userInfo: nil)
        }
        
        var data: [UInt8] = [UInt8(labelData.count)]
        data += [UInt8](labelData)
        
        let command = APDUCommand(cla: cla, ins: ins, p1: p1, p2: p2, data: data)
        
        do {
            let response = try self.cardTransmit(plainApdu: command)
            return response.sw1 == 0x90 && response.sw2 == 0x00
        } catch {
            return false
        }
    }
    
    // WARNING: this command can erase all data on card!
    public func cardSendResetCommand() throws -> APDUResponse {
        print("in cardSendResetCommand START")
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.resetToFactory.rawValue, p1: 0x00, p2: 0x00, data: [])
        
        //let rapdu = try self.cardTransmit(plainApdu: capdu)
        let rapdu = try self.cardChannel.send(capdu)
        print("in cardSendResetCommand END")
        
        return rapdu
    }
    
    //****************************************
    //*          MARK: PIN MGMT              *
    //****************************************
    
    public func cardChangePIN(oldPin: [UInt8], newPin: [UInt8]) throws -> APDUResponse {
        NSLog("In cardChangePIN")
        NSLog("Local package")
        let cla: UInt8 = CLA.proprietary.rawValue
        let ins: UInt8 = SatocardINS.changePin.rawValue
        let p1: UInt8 = 0x00//UInt8(newPin.count)
        let p2: UInt8 = 0x00
                
        let data: [UInt8] = [UInt8(oldPin.count)] + oldPin + [UInt8(newPin.count)] + newPin
        
        let command = APDUCommand(cla: cla, ins: ins, p1: p1, p2: p2, data: data)
        let response = try self.cardTransmit(plainApdu: command)
                
        return response
    }

    
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
        } catch CardError.wrongPIN(let retryCounter) {
            self.pin0 = nil
            //logger.info("SATOCHIPLIB: cardVerifyPIN: wrong pin: retryCounter \(retryCounter)")
            throw CardError.wrongPIN(retryCounter: retryCounter)
        } catch CardError.wrongPINLegacy {
            self.pin0 = nil
            //logger.info("SATOCHIPLIB: cardVerifyPIN: wrong pin (legacy: retryCounter unspecified)")
            throw CardError.wrongPINLegacy
        } catch CardError.pinBlocked {
            print("SATOCHIPLIB: cardVerifyPIN: pin blocked!")
            self.pin0 = nil
            throw CardError.pinBlocked
        }
        
        return rapdu
    }
    
    public func cardUnblockPIN(puk: [UInt8]) throws -> APDUResponse {
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: SatocardINS.unblockPin.rawValue, p1: 0x00, p2: 0x00, data: puk)
        //logger.info("SATOCHIPLIB: CAPDU cardUnblockPIN: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU cardUnblockPIN: \(rapdu.toHexString())")
        
        try rapdu.checkAuthOK()
        
        return rapdu
    }
    
    //****************************************
    //*           MARK: PKI                  *
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
    //*           MARK: CARD SETUP           *
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
    //*               MARK: BIP32
    //****************************************
    
    /**
     * The function computes the Bip32 extended key derived from a masterseed and returns either the
     * 32-bytes x-coordinate of the public key, or the 32-bytes private key, signed by the authentikey.
     *
     * The Path for the derivation is provided in the apdu data.
     *
     * - parameter path:
     * - parameter sid: for Seedkeeper, this is the secret_id of the masterseed that we want to use for derivation
     * - parameter optionFlags: byte mask that defines BIP32 configuration
     *      0x80: (deprecated: reset the bip32 cache memory)
     *      0x40: (deprecated: optimize non-hardened child derivation)
     *      0x20: (deprecated: flag whether to store key as object)
     *      0x10: RFU
     *      0x01: if set, use secure export (currently not supported!), otherwise use plain export
     *      0x02: if set, return privkey bytes (seedkeeper only), else public key
     *      0x04: if set, add final BIP85 HMAC derivation (seedkeeper only)
     *      0x08: RFU
     *
     * - Returns: Response adpu & SeedkeeperSecretObject data
     * */
    public func cardBip32GetExtendedkey(path: String, sid: Int? = nil, optionFlags: UInt8 = UInt8(0x40)) throws -> ([UInt8],[UInt8]) {
        print("[SatocardCommandSet.cardBip32GetExtendedkey]")
        let (depth, pathBytes) = try satochipParser.parseBip32PathToBytes(bip32path: path)
        guard depth <= 10 else {
            throw SatocardError.pathTooLongForBip32Derivation(length: depth, expected: 10)
        }
        
        let cla = CLA.proprietary.rawValue
        let ins = SatocardINS.bip32GetExtendedKey.rawValue
        let p1 = UInt8(depth)
        var p2 = optionFlags
        var data: [UInt8] = pathBytes
        if let sid = sid {
            data += [UInt8((sid>>8)%256), UInt8(sid%256)]
        }
        
        while (true) {
            var capdu: APDUCommand = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
            var rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
            
            // if there is no more memory available, erase cache  (for Satochip v<?)
            if (rapdu.sw == 0x9C01){
                print("[SatocardCommandSet.cardBip32GetExtendedkey] Reset memory...")
                // reset memory flag
                p2 = p2 ^ UInt8(0x80)
                capdu = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
                rapdu = try self.cardTransmit(plainApdu: capdu)
                // reset the flag then restart
                p2 = optionFlags
                continue
            }
            // other (unexpected) error
            if (rapdu.sw != 0x9000){
                throw SatocardError.unexpectedErrorDuringBip32Derivation(sw: Int(rapdu.sw))
            }
            // success
            if (rapdu.sw == 0x9000){
                print("[SatocardCommandSet.cardBip32GetExtendedkey] return 0x9000...")
                let response = rapdu.data
                if (optionFlags & UInt8(0x04)) == UInt8(0x04){ // BIP85
                    let (entropyBytes, emptyBytes) = try satochipParser.parseBip32GetExtendedBip85Key(response: response)
                    return (entropyBytes, emptyBytes)
                } else if (optionFlags & UInt8(0x02)) == UInt8(0x00) { // BIP32 pubkey
                    if ((response[32] & UInt8(0x80)) == UInt8(0x80)){
                        print("[SatocardCommandSet.cardBip32GetExtendedkey] Child Derivation optimization...")//debugSatochip
                        // todo
                        throw SatocardError.unsupportedLegacyOptionDuringBip32Derivation
                    }
                    let (pubkeyBytes, chaincodeBytes) = try satochipParser.parseBip32GetExtendedKey(response: response)
                    return (pubkeyBytes, chaincodeBytes)
                } else{ // BIP32 privkey
                    let (privkeyBytes, chaincodeBytes) = try satochipParser.parseBip32GetExtendedPrivkey(response: response)
                    return (privkeyBytes, chaincodeBytes)
                }
            }
        } // while
    }
    
    /**
     * Get the BIP32 xpub for given path.
     *
     * - parameter path: the bip32 path used for derivation, provided as string (path is of the form "m/44'/0'/1'")
     * - parameter xtype: the xpub header for mainnet or testnet
     * - parameter sid: for Seedkeeper, this is the secret_id of the masterseed that we want to use for derivation
     *
     * - returns: xpub: the corresponding xpub value as a string
     */
    public func cardBip32GetXpub(path: String, xtype: UInt32, sid: Int? = nil) throws -> (String){
        print("[SatocardCommandSet.cardBip32GetXpub] path: \(path)")
        
        var (childPubkey, childChaincode) = try cardBip32GetExtendedkey(path: path, sid: sid)
        // pubkey should be in compressed form
        if childPubkey.count != 33 {
            //throw SatocardError.wrongPubkeyLength(length: parentPubkeyBytes.count, expected: 33)
            childPubkey = try satochipParser.compressPubkey(pubkey: childPubkey)
        }
        
        // default values for masterkey (if depth == 0)
        let (depth, bytepath) = try satochipParser.parseBip32PathToBytes(bip32path: path)
        var fingerprintBytes = [UInt8](repeating: 0, count: 4)
        var childNumberBytes = [UInt8](repeating: 0, count: 4)
        if depth > 0 {
            // get parent info
            let parentPath = try satochipParser.getBip32PathParentPath(bip32path: path)
            print("[SatocardCommandSet.cardBip32GetXpub] parentPathString: \(parentPath)")
            var (parentPubkeyBytes, parentChaincodeBytes) = try cardBip32GetExtendedkey(path: parentPath,
                                                                                        sid: sid,
                                                                                        optionFlags: UInt8(0x40))
            // pubkey should be in compressed form
            if parentPubkeyBytes.count != 33 {
                //throw SatocardError.wrongPubkeyLength(length: parentPubkeyBytes.count, expected: 33)
                parentPubkeyBytes = try satochipParser.compressPubkey(pubkey: parentPubkeyBytes)
            }
            
            fingerprintBytes = Array(RIPEMD160.hash(message: Crypto.shared.sha256(parentPubkeyBytes))[0..<4])
            childNumberBytes = Array(bytepath[(bytepath.count-4)..<(bytepath.count)])
        }
        
        let xpubBytes = xtype.toBytes + [UInt8(depth)] + fingerprintBytes + childNumberBytes + childChaincode + childPubkey
        if xpubBytes.count != 78 {
            throw SatocardError.wrongXpubLength(length: xpubBytes.count, expected: 78)
        }
        
        let xpub = Base58.base58CheckEncode(xpubBytes)
        print("[SatocardCommandSet.cardBip32GetXpub] xpub: \(xpub)")
        return xpub
    }
    
    /**
     * Get the BIP32 xpriv for given path.
     * Only suitable for Seedkeeper, Satochip does NOT allow export of private keys by design.
     *
     * - parameter path: the bip32 path used for derivation, provided as string (path is of the form "m/44'/0'/1'")
     * - parameter xtype: the xpriv header for mainnet or testnet
     * - parameter sid: for Seedkeeper, this is the secret_id of the masterseed that we want to use for derivation
     *
     * - returns: xpriv: the corresponding xpriv value as a string
     */
    public func cardBip32GetXprv(path: String, xtype: UInt32, sid: Int? = nil) throws -> (String){
        print("[SatocardCommandSet.cardBip32GetXprv] path: \(path)")
        
        var (childPrivkey, childChaincode) = try cardBip32GetExtendedkey(path: path, sid: sid, optionFlags: UInt8(0x02))
        
        // default values for masterkey (if depth == 0)
        let (depth, bytepath) = try satochipParser.parseBip32PathToBytes(bip32path: path)
        var fingerprintBytes = [UInt8](repeating: 0, count: 4)
        var childNumberBytes = [UInt8](repeating: 0, count: 4)
        if depth > 0 {
            // get parent info
            let parentPath = try satochipParser.getBip32PathParentPath(bip32path: path)
            print("[SatocardCommandSet.cardBip32GetXprv] parentPathString: \(parentPath)")
            var (parentPubkeyBytes, parentChaincodeBytes) = try cardBip32GetExtendedkey(path: parentPath,
                                                                                        sid: sid,
                                                                                        optionFlags: UInt8(0x40))
            // pubkey should be in compressed form
            if parentPubkeyBytes.count != 33 {
                parentPubkeyBytes = try satochipParser.compressPubkey(pubkey: parentPubkeyBytes)
            }
            fingerprintBytes = Array(RIPEMD160.hash(message: Crypto.shared.sha256(parentPubkeyBytes))[0..<4])
            print("[SatocardCommandSet.cardBip32GetXprv] fingerprintBytes: \(fingerprintBytes.bytesToHex)")
            
            childNumberBytes = Array(bytepath[(bytepath.count-4)..<(bytepath.count)])
        }
        
        var xprvBytes = xtype.toBytes + [UInt8(depth)] + fingerprintBytes 
        xprvBytes += childNumberBytes + childChaincode + [UInt8(0)] + childPrivkey
        print("[SatocardCommandSet.cardBip32GetXprv] xprvBytes: \(xprvBytes.bytesToHex)")
        
        if xprvBytes.count != 78 {
            throw SatocardError.wrongXpubLength(length: xprvBytes.count, expected: 78)
        }
        
        let xprv = Base58.base58CheckEncode(xprvBytes)
        print("[SatocardCommandSet.cardBip32GetXprv] xprv: \(xprv)")
        return xprv
    }
    
//    def card_bip32_get_xprv(self, path, xtype, is_mainnet, sid=None):
//            
//            logger.info(f"card_bip32_get_xpriv(): path={str(path)}")#debugSatochip
//            if (type(path)==str):
//                (depth, bytepath)= self.parser.bip32path2bytes(path)
//            
//            option_flags= 0x02 # request privkey
//            (childkey, childchaincode)= self.card_bip32_get_extendedkey(bytepath, sid, option_flags)
//            if depth == 0: #masterkey
//                fingerprint= bytes([0,0,0,0])
//                child_number= bytes([0,0,0,0])
//            else: #get parent info
//                (parentkey, parentchaincode)= self.card_bip32_get_extendedkey(bytepath[0:-4], sid, option_flags)
//                fingerprint= hash_160(parentkey.get_public_key_bytes(compressed=True))[0:4]
//                child_number= bytepath[-4:]
//            
//            xprv_header= XPRV_HEADERS_MAINNET[xtype] if is_mainnet else XPPRV_HEADERS_TESTNET[xtype]
//            xprv = bytes.fromhex(xprv_header) + bytes([depth]) + fingerprint + child_number + childchaincode + bytes([0x00]) + childkey.get_private_key_bytes()
//            assert(len(xprv)==78)
//            xprv= EncodeBase58Check(xprv)
//            logger.info(f"card_bip32_get_xpub(): xprv={str(xprv)}")#debugSatochip
//            return xprv

    
    //****************************************
    //*               MARK: SATOCHIP
    //****************************************
    
    // Todo!
    
    //****************************************
    //*               MARK: SATODIME
    //****************************************
    
    public func satodimeGetStatus() throws -> APDUResponse {
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, 
                                             ins: SatocardINS.getSatodimeStatus.rawValue,
                                             p1: 0x00,
                                             p2: 0x00)
        
        //logger.info("SATOCHIPLIB: CAPDU satodimeGetStatus: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU satodimeGetStatus: \(rapdu.toHexString())")
        
        self.satodimeStatus = try SatodimeStatus(rapdu: rapdu)
        
        //return (rapdu, satodimeStatus)
        return rapdu
    }
    
    public func satodimeGetKeyslotStatus(keyNbr: UInt8) throws -> APDUResponse {
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, 
                                             ins: SatocardINS.getSatodimeKeyslotStatus.rawValue,
                                             p1: keyNbr,
                                             p2: 0x00)
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
    //*           MARK: SEEDKEEPER
    //****************************************
    
    /**
     Return status info specific to Seedkeeper

     - Returns: Response adpu & SeedkeeperStatus data
    */
    public func seedkeeperGetStatus() throws -> (APDUResponse, SeedkeeperStatus) {
        
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, 
                                             ins: SatocardINS.getSeedkeeperStatus.rawValue,
                                             p1: 0x00,
                                             p2: 0x00)
        //logger.info("SATOCHIPLIB: CAPDU seedkeeperGetStatus: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU seedkeeperGetStatus: \(rapdu.toHexString())")
        try rapdu.checkOK()
        let seedkeeperStatus = try SeedkeeperStatus(rapdu: rapdu)
        
        return (rapdu, seedkeeperStatus)
    }
    
    /**
     This function generates a master seed randomly within the Seedkeeper
     DEPRECATED: use only for Seedkeeper v0.1, for Seedkeeper v0.2, use preferrably seedkeeperGenerateRandomSecret()
     
     - parameter seedSize: seed size in byte (between 16-64)
     - parameter exportRights: export rights for generated secret
     - parameter label: label
     
     - Returns: Response adpu & SeedkeeperSecretHeader data
    */
    public func seedkeeperGenerateMasterseed(seedSize: Int, exportRights: SeedkeeperExportRights, label: String) throws -> (APDUResponse, SeedkeeperSecretHeader) {
        
        let labelBytes: [UInt8] = label.bytes
        let data: [UInt8] = [UInt8(labelBytes.count)] + labelBytes
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue,
                                             ins: SatocardINS.generateMasterseed.rawValue,
                                             p1: UInt8(seedSize),
                                             p2: exportRights.rawValue,
                                             data: data)
        //logger.info("SATOCHIPLIB: CAPDU seedkeeperGenerateMasterseed: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU seedkeeperGenerateMasterseed: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        let response: [UInt8] = rapdu.data
        let responseLength: Int = response.count
        let expectedLength = 6 //
        if (responseLength<expectedLength){
            throw SatocardError.wrongResponseLength(length: responseLength, expected: expectedLength)
        }
        let sid = 256*Int(response[0])+Int(response[1])
        let fingerprintBytes = Array(response[2..<6])
        let header = SeedkeeperSecretHeader(sid: sid,
                                            type: SeedkeeperSecretType.masterseed,
                                            subtype: 0,
                                            origin: SeedkeeperSecretOrigin.generatedOnCard,
                                            exportRights: exportRights,
                                            nbExportPlaintext: 0,
                                            nbExportEncrypted: 0,
                                            useCounter: 0,
                                            fingerprintBytes: fingerprintBytes,
                                            label: label)
        
        return (rapdu, header)
    }
    
    
    /**
     This function generates a 2FA secret (20 bytes) randomly within the Seedkeeper
     DEPRECATED: use only for Seedkeeper v0.1, for Seedkeeper v0.2, use preferrably seedkeeperGenerateRandomSecret()
     
     - parameter exportRights: export rights for generated secret
     - parameter label: label
     
     - Returns: Response adpu & SeedkeeperSecretHeader data
    */
    public func seedkeeperGenerate2faSecret(exportRights: SeedkeeperExportRights, label: String) throws -> (APDUResponse, SeedkeeperSecretHeader) {
        
        let labelBytes: [UInt8] = label.bytes
        let data: [UInt8] = [UInt8(labelBytes.count)] + labelBytes
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue,
                                             ins: SatocardINS.generate2FaSecret.rawValue,
                                             p1: 0x00,
                                             p2: exportRights.rawValue,
                                             data: data)
        //logger.info("SATOCHIPLIB: CAPDU seedkeeperGenerate2faSecret: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU seedkeeperGenerate2faSecret: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        let response: [UInt8] = rapdu.data
        let responseLength: Int = response.count
        let expectedLength = 6 //
        if (responseLength<expectedLength){
            throw SatocardError.wrongResponseLength(length: responseLength, expected: expectedLength)
        }
        let sid = 256*Int(response[0])+Int(response[1])
        let fingerprintBytes = Array(response[2..<6])
        
        let header = SeedkeeperSecretHeader(sid: sid,
                                            type: SeedkeeperSecretType.secret2FA,
                                            subtype: 0,
                                            origin: SeedkeeperSecretOrigin.generatedOnCard,
                                            exportRights: exportRights,
                                            nbExportPlaintext: 0,
                                            nbExportEncrypted: 0,
                                            useCounter: 0,
                                            fingerprintBytes: fingerprintBytes,
                                            label: label)
        
        return (rapdu, header)
    }
    
    /**
     This function generates a random secret randomly within the Seedkeeper. 
     Secret can be of type MasterSeed, MasterPassword or secret2FA.
     
     COMPATIBILITY: only supported in Seedkeeper v0.2 and higher.
     For Seedkeeper v0.1, some similar functionalities are available through seedkeeperGenerate2faSecret() or seedkeeperGenerateMasterseed()
        
     - parameter stype: secret type
     - parameter subtype: secret subtype
     - parameter size: secret size
     - parameter saveEntropy: save the entropy
     - parameter entropy: secret size
     - parameter exportRights: export rights for generated secret
     - parameter label: label for the secret
     
     - Returns: Response adpu & SeedkeeperSecretHeader data. If saveEntropy is true, returns SeedkeeperSecretHeader for the entropy secret
    */
    public func seedkeeperGenerateRandomSecret(stype: SeedkeeperSecretType,
                                               subtype: UInt8,
                                               size: UInt8,
                                               saveEntropy: Bool,
                                               entropy: [UInt8],
                                               exportRights: SeedkeeperExportRights,
                                               label: String) throws -> (APDUResponse, [SeedkeeperSecretHeader]) {
        
        if (size<16 || size>64){
            throw SeedkeeperApiError.wrongSecretSize(size: Int(size))
        }
        
        let labelBytes: [UInt8] = label.bytes
        let entropyBytes: [UInt8] = entropy.bytes
        let saveEntropyByte = saveEntropy ? UInt8(0x01) : UInt8(0x00)
        let data: [UInt8] = [stype.rawValue, subtype, saveEntropyByte] +
                            [UInt8(labelBytes.count)] + labelBytes + [UInt8(entropyBytes.count)] + entropyBytes
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue,
                                             ins: SatocardINS.generateRandomSecret.rawValue,
                                             p1: size,
                                             p2: exportRights.rawValue,
                                             data: data)
        //logger.info("SATOCHIPLIB: CAPDU seedkeeperGenerateRandomSecret: \(capdu.toHexString())")
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        //logger.info("SATOCHIPLIB: RAPDU seedkeeperGenerateRandomSecret: \(rapdu.toHexString())")
        
        try rapdu.checkOK()
        let response: [UInt8] = rapdu.data
        let responseLength: Int = response.count
        let expectedLength = saveEntropy ? 12 : 6
        if (responseLength<expectedLength){
            throw SatocardError.wrongResponseLength(length: responseLength, expected: expectedLength)
        }
        let sid = 256*Int(response[0])+Int(response[1])
        let fingerprintBytes = Array(response[2..<6])
        
        let header = SeedkeeperSecretHeader(sid: sid,
                                            type: stype,
                                            subtype: subtype,
                                            origin: SeedkeeperSecretOrigin.generatedOnCard,
                                            exportRights: exportRights,
                                            nbExportPlaintext: 0,
                                            nbExportEncrypted: 0,
                                            useCounter: 0,
                                            fingerprintBytes: fingerprintBytes,
                                            label: label)
        // entropy secret header
        if responseLength>=12 {
            let sid2 = 256*Int(response[6])+Int(response[7])
            let fingerprint2Bytes = Array(response[8..<12])
            
            let header2 = SeedkeeperSecretHeader(sid: sid2,
                                                 type: SeedkeeperSecretType.key,
                                                 subtype: SeedkeeperKeySubtype.entropy.rawValue, //UInt8(0x10),
                                                 origin: SeedkeeperSecretOrigin.generatedOnCard,
                                                 exportRights: exportRights,
                                                 nbExportPlaintext: 0,
                                                 nbExportEncrypted: 0,
                                                 useCounter: 0,
                                                 fingerprintBytes: fingerprint2Bytes,
                                                 label: "entropy")
            return (rapdu, [header, header2])
        }
        
        return (rapdu, [header])
    }
    
    /**
     This function derives and export a secret (password) from a master password and provided salt.
     Derivation is done using HMAC-SHA512 using the salt as key and master password as message.
     Currently, only plaintext export is suported
     
     COMPATIBILITY: only supported in Seedkeeper v0.2 and higher
        
     - parameter salt: bytes used to uniquely derive master password
     - parameter sid: sid of MasterPassword
     - parameter sidPubkey: sid of pubkey for encrypted export
     
     - Returns: Response adpu 
     - Returns: derived password data
    */
    public func seedkeeperDeriveMasterPassword(salt: [UInt8],
                                               sid: Int,
                                               sidPubkey: Int? = nil) throws -> (APDUResponse, SeedkeeperDerivedSecret) {
        print("SATOCHIPLIB: seedkeeperDeriveMasterPassword")
        
        let isSecureExport = (sidPubkey == nil) ? false : true
        if (isSecureExport){
            throw SatocardError.unsupportedFeature(msg: "secure_export currently unsupported for seedkeeper_derive_master_password")
        }
        
        //data: [ master_password_sid(2b) | salt_size(1b) | salt_used_for_derivation (max 128 bytes) ]
        let data: [UInt8] = [UInt8((sid>>8)%256), UInt8(sid%256)] + [UInt8(salt.count)] + salt
        let capdu: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue,
                                             ins: SatocardINS.deriveMasterPassword.rawValue,
                                             p1: isSecureExport ? 0x02 : 0x01,
                                             p2: 0x00,
                                             data: data)
        
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        try rapdu.checkOK()
        
        // response: [ derived_data_size(2b) | derived_data | sig_size(2b) | authentikey_sig]
        let response: [UInt8] = rapdu.data
        let responseLength: Int = response.count
        
        if (responseLength<2){
            throw SatocardError.wrongResponseLength(length: responseLength, expected: 2)
        }
        let secretSize = 256*Int(response[0])+Int(response[1])
        if (responseLength<2+secretSize+2){
            throw SatocardError.wrongResponseLength(length: responseLength, expected: 2+secretSize+2)
        }
        
        var offset = 2
        let secret: [UInt8] = Array(response[offset..<(offset+secretSize)])
        offset+=secretSize
        
        let sigSize = 256*Int(response[offset])+Int(response[offset+1])
        offset+=2
        if (responseLength<2+secretSize+2+sigSize){
            throw SatocardError.wrongResponseLength(length: responseLength, expected: 2+secretSize+2+sigSize)
        }
        
        let sig: [UInt8] = Array(response[offset..<(offset+sigSize)])
        // todo: check sig
        
        let derivedSecret = SeedkeeperDerivedSecret(sid: sid,
                                                    salt: salt,
                                                    secret: secret,
                                                    sig: sig)
        return (rapdu, derivedSecret)
    }
    
    
    /**
     This function imports a secret in plaintext/encrypted from host.

     Note for Seedkeeper v0.2 and higher:
     During the init phase, secret_size must be provided so that exact amount of memory can be allocated.
     This secret_size is the size that the **encrypted** secret will occupy in memory (using AES ECB with **padding**).
     For secure import, secret is already encrypted, thus secret_size is simply the size of the encrypted secret (in bytes)
     For plain import, secret will be encrypted in memory, so a padding of (AES_BLOCKSIZE - plain_secret_size%AES_BLOCKSIZE) must be added.
     
     - parameter secretObject: SeedkeeperSecretObject with the secret & metadata
     - parameter sidPubkey: for secure import, the id of the pubkey used for export
        
     - returns: responseAPDU
     - returns: id
     - returns: fingerprint (4bytes)
     */
    public func seedkeeperImportSecret(secretObject: SeedkeeperSecretObject, sidPubkey: Int? = nil) throws -> (APDUResponse, Int, [UInt8])  {
        print("SATOCHIPLIB: seedkeeperImportSecret")
        
        let secretHeader = secretObject.secretHeader
        //let sidPubkey: Int? = secretObject.secretEncryptedParams?.sidPubkey //(secretObject.SecretEncryptedParams == nil) ? nil : secretObject.SecretEncryptedParams?.sidPubkey
        let isSecureExport = (sidPubkey == nil) ? false : true
        let secretBytes: [UInt8] = secretObject.secretBytes
        var secretPaddedSize = 0
        if (isSecureExport){
            secretPaddedSize = secretBytes.count // encrypted_secret is already padded!
        }
        else {
            let secretSize = secretBytes.count
            let padSize = 16 - (secretSize)%16
            secretPaddedSize = secretSize + padSize // padded_secret_size is size of encrypted secret (including padding)
        }
        
        let cla = CLA.proprietary.rawValue
        let ins = SatocardINS.importSecret.rawValue
        let p1 = isSecureExport ? UInt8(0x02) : UInt8(0x01)
        
        // OP_INIT
        var p2 = UInt8(0x01)
        // for Seedkeeper v0.1 only:
        // data= [secret_type, export_rights, rfu1, rfu2, label_size] + label_list + [(sid_pubkey>>8)%256, sid_pubkey%256] + iv
        // for Seedkeeper v0.2 (backward compatible with v0.1):
        // data= [secret_type, export_rights, rfu1, rfu2, label_size] + label_list + [(sid_pubkey>>8)%256, sid_pubkey%256] + iv + padded_secret_size(2b)
        var data: [UInt8] = secretObject.secretHeader.getHeaderBytes()
        if (isSecureExport){
            if let sidPubkey = sidPubkey {
                data += [UInt8(sidPubkey>>8), UInt8(sidPubkey%256)]
            }
            if let params = secretObject.secretEncryptedParams {
                data += params.iv
            }
        }
        data += [UInt8((secretPaddedSize>>8)%256), UInt8(secretPaddedSize%256)]
        var capdu: APDUCommand = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
        var rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        try rapdu.checkOK()
        
        // OP_PROCESS
        p2 = UInt8(0x02)
        let chunkSize = 128
        var secretOffset = 0
        var secretRemaining = secretBytes.count
        while (secretRemaining > chunkSize){
            data = [UInt8(chunkSize>>8), UInt8(chunkSize%256)] + secretBytes[secretOffset..<(secretOffset+chunkSize)]
            capdu = APDUCommand(cla: cla, ins: ins, p1: p1, p2: p2, data: data)
            rapdu = try self.cardTransmit(plainApdu: capdu)
            try rapdu.checkOK()
            
            secretOffset += chunkSize
            secretRemaining -= chunkSize
        }
        
        // OP_FINAL
        p2 = UInt8(0x03)
        data = [UInt8(secretRemaining>>8), UInt8(secretRemaining%256)] + secretBytes[secretOffset..<(secretOffset+secretRemaining)]
        if (isSecureExport){
            if let params = secretObject.secretEncryptedParams {
                let hmacBytes = params.hmac
                data += [UInt8(hmacBytes.count)] + hmacBytes
            }
        }
        capdu = APDUCommand(cla: cla, ins: ins, p1: p1, p2: p2, data: data)
        rapdu = try self.cardTransmit(plainApdu: capdu)
        try rapdu.checkOK()
//        if (sw1==0x9C && sw2==0x33){
//            print("Error during secret import - OP_FINAL: wrong mac (error code {hex(256*sw1+sw2)})")
//            throw ("Error during secret import: wrong mac (error code {hex(256*sw1+sw2)})")
//        } else if (sw1!=0x90 && sw2!=0x00){
//            print("Error during secret import - OP_FINAL (error code \(hex(256*sw1+sw2))")
//            throw ("Unexpected error during secure secret import (error code {hex(256*sw1+sw2)})")
//        }
        secretOffset += secretRemaining
        secretRemaining -= 0
        
        // check fingerprint
        // response: [id(2b) | fingerprint(4b)]
        let response: [UInt8] = rapdu.data
        let responseLength: Int = response.count
        if (responseLength<6){
            throw SatocardError.wrongResponseLength(length: responseLength, expected: 6)
        }
        
        let sid = 256*Int(response[0])+Int(response[1])
        let fingerprintFromSeedkeeper = Array(response[2..<6])
        var fingerprintFromSecret: [UInt8] = secretObject.getFingerprintFromSecret()
//        if (isSecureExport){
//            fingerprintFromSecret = secretHeader.fingerprintBytes
//        } else {
//            fingerprintFromSecret = secretObject.getFingerprintFromSecret()
//            //let secretHash = Crypto.shared.sha256(secretBytes)
//            //fingerprintFromSecret = Array(secretHash[0..<4]) //hashlib.sha256(bytes(secret_list)).hexdigest()[0:8]
//        }
        if (fingerprintFromSecret == fingerprintFromSeedkeeper ){
            print("SATOCHIPLIB seedkeeperImportSecret: Fingerprints match!")
        } else {
            print("SATOCHIPLIB seedkeeperImportSecret: Fingerprint mismatch: expected \(fingerprintFromSecret) but recovered \(fingerprintFromSeedkeeper)")
        }
        
        return (rapdu, sid, fingerprintFromSeedkeeper)
    }
    
    /**
     * This function exports a secret in plaintext or encrypted from the Seedkeeper to the host.
     * For plaintext export, data is encrypted during transport through the Secure Channel but the host has access to the data in plaintext.
     * For secure export, an encryption key is generated using ECDH and used to encrypt secret (in addition the secure channel).
     * For export of a Masterseed to a Satochip, use the method seedkeeperExportSecretToSatochip() which performs optimizations to reduce the secret size.
     *
     * - parameter sid: id of the secret to export
     * - parameter sidPubkey: for secure export, the id of the pubkey used for export
     *
     * - returns secret: SeedkeeperSecretObject
     */
    public func seedkeeperExportSecret(sid: Int, sidPubkey:Int? = nil) throws -> (SeedkeeperSecretObject){
        print("SATOCHIPLIB: seedkeeperExportSecret")
        
        let isSecureExport = (sidPubkey == nil) ? false : true
        
        let cla = CLA.proprietary.rawValue
        let ins = SatocardINS.exportSecret.rawValue
        let p1 = isSecureExport ? UInt8(0x02) : UInt8(0x01)
        
        // OP_INIT
        var p2 = UInt8(0x01)
        var data = [UInt8(sid>>8), UInt8(sid%256)]
        if let sidPubkey = sidPubkey {
            data += [UInt8(sidPubkey>>8), UInt8(sidPubkey%256)]
        }
        var capdu: APDUCommand = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
        var rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        try rapdu.checkOK()
        
        // parse header
        var response = rapdu.data
        let secretHeader = try SeedkeeperSecretHeader(response: response)
        // iv
        var iv: [UInt8] = []
        if (isSecureExport){
            iv =  Array(response.suffix(16))
        }
        
        // OP_PROCESS
        p2 = UInt8(0x02)
        data = []
        var secretBytes: [UInt8] = []
        var sigSize = 0
        var sigBytes: [UInt8] = []
        while(true){
            capdu = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
            rapdu = try self.cardTransmit(plainApdu: capdu)
            try rapdu.checkOK()
            
            // parse response
            response = rapdu.data
            let responseSize = response.count
            let chunkSize = 256*Int(response[0]) + Int(response[1])
            let chunk = Array(response[2..<(2+chunkSize)])
            secretBytes += chunk
            
            // check if last chunk
            if (chunkSize+2<responseSize){
                var offset = chunkSize+2
                sigSize = 256*Int(response[offset])+Int(response[offset+1])
                offset += 2
                sigBytes = Array(response[offset..<(offset+sigSize)])
                break
            }
        }
        
        // todo: check sig
        
        // create secretObject
        let secretEncryptedParams = isSecureExport ? SeedkeeperSecretEncryptedParams(iv: iv, hmac: sigBytes) : nil
        let secretObject = SeedkeeperSecretObject(secretBytes: secretBytes,
                                                  secretHeader: secretHeader,
                                                  isEncrypted: isSecureExport,
                                                  secretEncryptedParams: secretEncryptedParams)
        
        // check fingerprint (only possible for plaintext export)
        if !isSecureExport {
            let fingerprintFromSeedkeeper = secretHeader.fingerprintBytes
            //let secretHash = Crypto.shared.sha256(secretBytes)
            //let fingerprintFromSecret: [UInt8] = Array(secretHash[0..<4])
            let fingerprintFromSecret: [UInt8] = secretObject.getFingerprintFromSecret()
            
            if (fingerprintFromSecret == fingerprintFromSeedkeeper ){
                print("SATOCHIPLIB seedkeeperExportSecret: Fingerprints match!")
            } else {
                print("SATOCHIPLIB seedkeeperExportSecret: Fingerprint mismatch: expected \(fingerprintFromSecret) but recovered \(fingerprintFromSeedkeeper)")
            }
        }
        
        return (secretObject)
    }
    
    /**
     * This function exports a secret from a Seedkeeper for secure import to a Satochip.
     * The secret is encrypted with a key is generated with ECDH, using the Satochip authentikey.
     * Compared to the seedkeeperExportSecret() method, this method is executed in one phase, and the secret size is reduced to the minimum (max 64b).
     * Only Masterseeds & 2FA secrets can be exported this way. The secret is always exported encrypted.
     *
     * - parameter sid: id of the secret to export
     * - parameter sidPubkey: the id of the satochip authentikey used for export
     *
     * - returns encrypted secret: SeedkeeperSecretObject
     */
    public func seedkeeperExportSecretToSatochip(sid: Int, sidPubkey: Int) throws -> (SeedkeeperSecretObject){
        print("SATOCHIPLIB: seedkeeperExportSecretToSatochip")
        let cla = CLA.proprietary.rawValue
        let ins = SatocardINS.exportSecretToSatochip.rawValue
        let p1 = UInt8(0x00)
        let p2 = UInt8(0x00)
        
        //data: [ id(2b) | idPubkey(2b) ]
        let data = [UInt8(sid>>8), UInt8(sid%256)] + [UInt8(sidPubkey>>8), UInt8(sidPubkey%256)]
        let capdu: APDUCommand = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        try rapdu.checkOK()
        
        // return: [ id(2b) | header(13b) | IV(16b) | encrypted_secret_size(2b) | encrypted_secret | hmac_size(2b) | hmac(20b) ]
        // parse header
        let response = rapdu.data
        let secretHeader = try SeedkeeperSecretHeader(response: response)
        // iv
        var offset = 15
        let iv: [UInt8] = Array(response[offset..<(offset+16)])
        offset += 16
        // secretSize
        let secretSize = Int(response[offset])*256 + Int(response[offset+1])
        offset += 2
        // encrypted secret
        let secretBytes = Array(response[offset..<(offset+secretSize)])
        offset += secretSize
        // hmac size
        let hmacSize = Int(response[offset])*256 + Int(response[offset+1])
        offset += 2
        // hmac
        let hmacBytes = Array(response[offset..<(offset+hmacSize)])
        
        // secretObject
        let secretParams = SeedkeeperSecretEncryptedParams(iv: iv, hmac: hmacBytes)
        let secretObject = SeedkeeperSecretObject(secretBytes: secretBytes,
                                                  secretHeader: secretHeader,
                                                  isEncrypted: true,
                                                  secretEncryptedParams: secretParams)
        
        return secretObject
    }
    
    /**
     * This function resets a secret object from Seedkeeper secure memory.
     *
     * - parameter sid: the id of the secret to erase
     *
     * - returns APDUResponse: the APDU response
     *
     * - throws: SW_OBJECT_NOT_FOUND if no object with given sid is found
     */
    public func seedkeeperResetSecret(sid: Int) throws -> (APDUResponse) {
        print("[SatocardCommandSet.seedkeeperResetSecret]")
        let cla = CLA.proprietary.rawValue
        let ins = SatocardINS.resetSecret.rawValue
        let p1 = UInt8(0x00)
        let p2 = UInt8(0x00)
        
        //data: [id(2b)]
        let data = [UInt8(sid>>8), UInt8(sid%256)]
        let capdu: APDUCommand = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
        let rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        try rapdu.checkOK()
        
        return rapdu
    }
    
    /**
     * This function list all the secrets stored in the Seedkeeper secure memory
     * Only the header data of each object is returned.
     * The sensitive data (which is encrypted) is not returned.
     *
     * - returns [SeedkeeperSecretHeader]: a list of secret header
     *
     */
    public func seedkeeperListSecretHeaders() throws ->([SeedkeeperSecretHeader]){
        print("[SatocardCommandSet.seedkeeperExportSecretToSatochip]")
        let cla = CLA.proprietary.rawValue
        let ins = SatocardINS.listSecretHeaders.rawValue
        let p1 = UInt8(0x00)
        let data: [UInt8] = []
        
        // OP_INIT
        var secretHeaders: [SeedkeeperSecretHeader] = []
        var p2 = UInt8(0x01)
        var capdu: APDUCommand = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
        var rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        
        while (rapdu.sw1==0x90 && rapdu.sw2==0x00){
            //return: [object_id(2b) | type(1b) | export_control(1b) | nb_export_plain(1b) | nb_export_secure(1b) | label_size(1b) | label ]
            let response = rapdu.data
            let secretHeader = try SeedkeeperSecretHeader(response: response)
            secretHeaders += [secretHeader]
            //todo: verif signature
            
            // next object
            p2 = 0x02
            capdu = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
            rapdu = try self.cardTransmit(plainApdu: capdu)
        }
        
        if (rapdu.sw1==0x9C && rapdu.sw2==0x12){
            print("[SatocardCommandSet.seedkeeperExportSecretToSatochip] No more object in memory")
        } else {
            print("[SatocardCommandSet.seedkeeperExportSecretToSatochip] Unexpected error during object listing (code \(String(rapdu.sw, radix: 16)))")
        }
        
        return secretHeaders
    }
    
    /**
     * This function returns the logs stored in the Seedkeeper card.
     * Log are returned starting with the most recent log first.
     *
     * - parameter printAll: Bool, print all logs if true, else only the last log
     *
     * - returns [SeedkeeperLog]: a list of logs
     * - returns Int: nbTotalLogs: the number of events logged in all the card life
     * - returns Int: nbAvailLogs: the number of logs available (stored)
     */
    public func seedkeeperPrintLogs(printAll: Bool = true) throws -> ([SeedkeeperLog], Int, Int){
        print("[SatocardCommandSet.seedkeeperPrintLogs]")
        let cla = CLA.proprietary.rawValue
        let ins = SatocardINS.printLogs.rawValue
        let p1 = UInt8(0x00)
        let data: [UInt8] = []
        
        // OP_INIT
        var p2 = UInt8(0x01)
        var capdu: APDUCommand = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
        var rapdu: APDUResponse = try self.cardTransmit(plainApdu: capdu)
        var response = rapdu.data
        
        // first log
        var logs: [SeedkeeperLog] = []
        var log: SeedkeeperLog
        var nbTotalLogs = 0
        var nbAvailLogs = 0
        if (rapdu.sw1==0x90 && rapdu.sw2==0x00){
            nbTotalLogs = Int(response[0])*256+Int(response[1])
            nbAvailLogs = Int(response[2])*256+Int(response[3])
            print("[SatocardCommandSet.seedkeeperPrintLogs] nbTotalLogs: \(nbTotalLogs)")
            print("[SatocardCommandSet.seedkeeperPrintLogs] nbAvailLogs: \(nbAvailLogs)")
            if response.count >= 4+SeedkeeperLog.logSize{
                log = try SeedkeeperLog(response: Array(response[4..<(4+SeedkeeperLog.logSize)]))
                logs += [log]
                print("[SatocardCommandSet.seedkeeperPrintLogs] latest log: \(log)")
            } else {
                print("No logs available!")
            }
        } else if (rapdu.sw1==0x9C && rapdu.sw2==0x04){
            print("[SatocardCommandSet.seedkeeperPrintLogs] no logs: Seedkeeper is not initialized!")
        } else {
            print("[SatocardCommandSet.seedkeeperPrintLogs] unexpected error during object listing (code \(String(rapdu.sw, radix: 16)))")
        }
        
        //next logs
        p2 = 0x02
        var counter=0
        while (printAll && rapdu.sw1==0x90 && rapdu.sw2==0x00){
            capdu = APDUCommand(cla: cla,ins: ins, p1: p1, p2: p2, data: data)
            rapdu = try self.cardTransmit(plainApdu: capdu)
            response = rapdu.data
            if (rapdu.sw1 != 0x90 || rapdu.sw2 != 0x00){
                print("[SatocardCommandSet.seedkeeperPrintLogs] Error during log printing: (code \(String(rapdu.sw, radix: 16)))")
                break
            }
            if (response.count==0){
                break
            }
            // parse response (can contain multiple logs)
            while (response.count >= SeedkeeperLog.logSize){
                log = try SeedkeeperLog(response: response)
                logs += [log]
                response = Array(response[SeedkeeperLog.logSize..<response.count])
                
                counter += 1
                if (counter>100){ // safe break; should never happen
                    print("[SatocardCommandSet.seedkeeperPrintLogs] Counter exceeded during log printing: {counter}")
                    break
                }
            }
        } // while
        
        return (logs, nbTotalLogs, nbAvailLogs)
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

