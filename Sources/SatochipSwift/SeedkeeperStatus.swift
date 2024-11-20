public enum SeedkeeperStatusError: Error {
    case wrongDataLength(length: Int, expected: Int)
}

public struct SeedkeeperStatus {
    
    public var nbSecrets : Int = 0
    public var totalMemory : Int = 0
    public var freeMemory : Int = 0
    public var nbLogsTotal : Int = 0
    public var nbLogsAvail : Int = 0
    public var lastLog: [UInt8] = [] // todo: SeedkeeperLog object
    
    public init() {}
    
    public init(rapdu: APDUResponse) throws {
        
        let sw = rapdu.sw
        if sw==0x9000 {
            var offset=0
            let data: [UInt8] = rapdu.data
            let dataLength: Int = data.count
            let expectedLength = 17 //
            
            if (dataLength<expectedLength){
                throw SeedkeeperStatusError.wrongDataLength(length: dataLength, expected: expectedLength)
            }
            
            // memory
            self.nbSecrets = 256*Int(data[offset]) + Int(data[offset+1])
            offset+=2
            self.totalMemory = 256*Int(data[offset]) + Int(data[offset+1])
            offset+=2
            self.freeMemory = 256*Int(data[offset]) + Int(data[offset+1])
            offset+=2
            // logs
            self.nbLogsTotal = 256*Int(data[offset]) + Int(data[offset+1])
            offset+=2
            self.nbLogsAvail = 256*Int(data[offset]) + Int(data[offset+1])
            offset+=2
            self.lastLog = Array(data[offset..<(offset+7)])
            offset+=7
        }
        else{
            // error
            if let statusWord = StatusWord(rawValue: sw) {
                throw statusWord
            } else {
                throw StatusWord.unknownError
            }
        }
    }
        
    public func toString() -> String {
        let status_info: String = "nbSecret: \(nbSecrets) \n" +
                                  "freeMemory: \(freeMemory) \n" +
                                  "totalMemory: \(totalMemory)) \n" +
                                  "nbLogsTotal: \(nbLogsTotal)) \n" +
                                  "nbLogsAvail: \(nbLogsAvail)) \n" +
                                  "lastLog: \(lastLog)"
        return status_info
    }
}
