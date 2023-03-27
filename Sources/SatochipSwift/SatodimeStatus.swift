public enum SatodimeStatusError: Error {
    case wrongDataLength(length: Int, expected: Int)
    case unknownError(sw: UInt16)
    case setupAlreadyDone
    case setupNotDone
}

public struct SatodimeStatus {
    
    public var setupDone: Bool = false
    public var isOwner: Bool = false
    public var maxNumKeys: Int = 0
    public var satodimeKeysState: [UInt8] = [UInt8]()
    public var unlockCounter: UInt32 = 0
    public var unlockSecret: [UInt8] = [UInt8](repeating: 0x00, count: SatocardCst.sizeUnlockSecret)
    
    public init() {}
    
    public init(rapdu: APDUResponse) throws {
        
        let sw = rapdu.sw
        if sw==0x9000 {
            
            //data: [unlock_counter | nb_keys_slots(1b) | key_status(nb_key_slots bytes) ]
            let data: [UInt8] = rapdu.data
            setupDone = true

            var offset: Int = 0
            var dataRemain: Int = data.count
            // unlock_counter
            if dataRemain<SatocardCst.sizeUnlockCounter {
                throw SatodimeStatusError.wrongDataLength(length: dataRemain, expected: SatocardCst.sizeUnlockCounter)
            }
            //self.unlockCounter = Array(data[0 ..< SatochipCst.sizeUnlockCounter])
            self.unlockCounter = data[0 ..< SatocardCst.sizeUnlockCounter].toUInt32
            offset+=SatocardCst.sizeUnlockCounter
            dataRemain-=SatocardCst.sizeUnlockCounter
            // max_num_keys
            if dataRemain<1 {
                throw SatodimeStatusError.wrongDataLength(length: dataRemain, expected: 1)
            }
            self.maxNumKeys = Int(data[offset])
            offset+=1
            dataRemain-=1
            // satodime_keys_state
            if dataRemain<self.maxNumKeys {
                throw SatodimeStatusError.wrongDataLength(length: dataRemain, expected: self.maxNumKeys)
            }
            self.satodimeKeysState = Array(data[offset ..< (offset+maxNumKeys)])
        }
        else if sw==StatusWord.setupNotDone.rawValue {
            setupDone = false
        }
        else{
            // todo??
            throw SatodimeStatusError.unknownError(sw: sw)
        }
    }

    public mutating func updateStatusFromSetup(rapdu: APDUResponse) throws {
        let sw = rapdu.sw
        if sw==StatusWord.ok.rawValue {
            setupDone = true
            let data: [UInt8] = rapdu.data
            var offset: Int = 0
            var dataRemain: Int = data.count
            if dataRemain<SatocardCst.sizeUnlockCounter {
                throw SatodimeStatusError.wrongDataLength(length: dataRemain, expected: SatocardCst.sizeUnlockCounter)
            }
            unlockCounter = data[offset ..< (offset+SatocardCst.sizeUnlockCounter)].toUInt32
            offset+=SatocardCst.sizeUnlockCounter
            dataRemain-=SatocardCst.sizeUnlockCounter
            if dataRemain<SatocardCst.sizeUnlockSecret {
                throw SatodimeStatusError.wrongDataLength(length: dataRemain, expected: SatocardCst.sizeUnlockSecret)
            }
            unlockSecret = Array(data[offset ..< (offset+SatocardCst.sizeUnlockSecret)])
            isOwner = true;
        }
        else if sw==StatusWord.setupNotDone.rawValue {
            setupDone = false
            throw SatodimeStatusError.setupNotDone
        }
        else if sw==StatusWord.setupAlreadyDone.rawValue {
            setupDone = true
            throw SatodimeStatusError.setupAlreadyDone
        }else {
            throw SatodimeStatusError.unknownError(sw: sw)
        }
    }
    
    public mutating func setUnlockSecret(unlockSecret: [UInt8]) {
        self.unlockSecret = unlockSecret
        self.isOwner = true
    }
    
    public mutating func incrementUnlockCounter(){
        self.unlockCounter+=1
    }
        
    public func computeUnlockCode(challenge: [UInt8]) -> [UInt8] {
        //logger.info("In computeUnlockCode counter: \(unlockCounter)")
        
        let unlockCounterBytes = unlockCounter.toBytes
        //logger.info("In computeUnlockCode counterBytes: \(unlockCounterBytes)")
        //logger.info("In computeUnlockCode counterBytes hex: \(unlockCounterBytes.bytesToHex)")
        let dataToMac: [UInt8] = challenge + unlockCounterBytes
        //logger.info("dataToMac: \(dataToMac.bytesToHex)")
        let macBytes: [UInt8] = Crypto.shared.hmacSHA1(data: dataToMac, key: unlockSecret)
        
        let response = unlockCounterBytes + macBytes
        return response
    }
    
    public func toString() -> String {
        let status_info: String = "setupDone: \(setupDone) \n" +
                                  "maxNumKeys: \(maxNumKeys) \n" +
                                  "satodimeKeysState: \(satodimeKeysState)) \n" +
                                  "unlockCounter: \(unlockCounter)"
        return status_info
    }
}
