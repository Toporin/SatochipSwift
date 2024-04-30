public enum SatodimeKeyslotStatusError: Error {
    case wrongDataLength(length: Int, expected: Int)
    case wrongContractLength(length: Int, expected: Int)
    case wrongTokenidLength(length: Int, expected: Int)
    case wrongMetadataLength(length: Int, expected: Int)
    case unknownError(sw: UInt16)
}

public enum SlotStatus: Int {
    case uninitialized = 0x00
    case sealed = 0x01
    case unsealed = 0x02
}

public struct SatodimeKeyslotStatus {
    
    public var setupDone: Bool = false
    public var type: UInt8 = 0
    public var status: UInt8 = 0
    public var asset: UInt8 = 0
    public var slip44: UInt32 = 0
    public var slip44Array: [UInt8] = [UInt8]()
    public var contract: [UInt8] = [UInt8]()
    public var tokenid: [UInt8] = [UInt8]()
    public var metadata: [UInt8] = [UInt8]()
    
    // info not provided from rapdu...
    public var index: UInt8 = 0xff
    
    public init(rapdu: APDUResponse) throws {
        
        let sw = rapdu.sw
        if sw==0x9000 {
            
            //data: [ key_status(1b) | key_type(1b) | key_asset(1b) | key_slip44(4b) | key_contract(34b) | key_tokenid(34b) | key_data(66b) ]
            let data = rapdu.data
            var offset = 0
            var dataRemain = data.count
            
            // keyStatus, keyType, keyAsset
            if dataRemain<3 {
                throw SatodimeKeyslotStatusError.wrongDataLength(length: dataRemain, expected: 3)
            }
            status = data[offset]
            offset+=1
            type = data[offset]
            offset+=1
            asset = data[offset]
            offset+=1
            dataRemain-=3

            // slip44
            if dataRemain<SatocardCst.sizeSlip44 {
                throw SatodimeKeyslotStatusError.wrongDataLength(length: dataRemain, expected: SatocardCst.sizeSlip44)
            }
            slip44Array = Array(data[offset ..< (offset+SatocardCst.sizeSlip44)])
            slip44 = slip44Array.toUInt32
            offset+=SatocardCst.sizeSlip44
            dataRemain-=SatocardCst.sizeSlip44
            
            // parse contract TLV bytes
            if dataRemain<SatocardCst.sizeContract {
                throw SatodimeKeyslotStatusError.wrongDataLength(length: dataRemain, expected: SatocardCst.sizeContract)
            }
            let contractRfu = data[offset] // contract[0] is RFU (contract type?)
            offset+=1
            let contractSize = Int(data[offset])
            offset+=1
            if contractSize > (SatocardCst.sizeContract-2) {
                throw SatodimeKeyslotStatusError.wrongContractLength(length: contractSize, expected: (SatocardCst.sizeContract-2))
            }
            contract = Array(data[offset ..< (offset+contractSize)])
            offset+=(SatocardCst.sizeContract-2)
            dataRemain-=SatocardCst.sizeContract
            
            // parse tokenid TLV bytes
            if dataRemain<SatocardCst.sizeTokenid {
                throw SatodimeKeyslotStatusError.wrongDataLength(length: dataRemain, expected: SatocardCst.sizeTokenid)
            }
            let tokenidRfu = data[offset] // tokenid[0] is RFU (tokenid type?)
            offset+=1
            let tokenidSize = Int(data[offset])
            offset+=1
            if tokenidSize > (SatocardCst.sizeTokenid-2) {
                throw SatodimeKeyslotStatusError.wrongTokenidLength(length: tokenidSize, expected: (SatocardCst.sizeTokenid-2))
            }
            tokenid = Array(data[offset ..< (offset+tokenidSize)])
            offset+=(SatocardCst.sizeTokenid-2)
            dataRemain-=SatocardCst.sizeTokenid
            
            // parse metadata TLV bytes
            if dataRemain<SatocardCst.sizeData {
                throw SatodimeKeyslotStatusError.wrongDataLength(length: dataRemain, expected: SatocardCst.sizeData)
            }
            let metadataRfu = data[offset] // metadata[0] is RFU (metadata type?)
            offset+=1
            let metadataSize = Int(data[offset])
            offset+=1
            if metadataSize > (SatocardCst.sizeData-2) {
                throw SatodimeKeyslotStatusError.wrongMetadataLength(length: metadataSize, expected: (SatocardCst.sizeData-2))
            }
            metadata = Array(data[offset ..< (offset+metadataSize)])
            offset+=(SatocardCst.sizeData-2)
            dataRemain-=SatocardCst.sizeData
   
            setupDone = true
            
        } else if (sw==0x9c04){
            setupDone = false
        } else{
            throw SatodimeKeyslotStatusError.unknownError(sw: sw)
        }
    }
    
    public mutating func setKeyslotIndex(index: UInt8) {
        self.index = index
    }
    
    // to string
    public func toString() -> String {
        let keyslotInfo = "keyslotIndex: \(index) \n" +
                          "setupDone: \(setupDone) \n" +
                          "keyStatus: \(status) \n" +
                          "keyType:  \(type) \n" +
                          "keyAsset: \(asset) \n" +
                          "keySlip44: \(slip44Array.bytesToHex) \n" +
                          "keyContract: \(contract.bytesToHex) \n" +
                          "keyTokenId: \(tokenid.bytesToHex) \n" +
                          "keyData: \(metadata.bytesToHex) \n"
        return keyslotInfo
    }

}
