
public struct CardStatus {

    public var setupDone: Bool = false
    public var isSeeded: Bool = false
    public var needsSecureChannel: Bool = false
    public var needs2FA: Bool = false
    public var protocolMajorVersion: UInt8 = 0
    public var protocolMinorVersion: UInt8 = 0
    public var appletMajorVersion: UInt8 = 0
    public var appletMinorVersion: UInt8 = 0
    public var pin0RemainingTries: UInt8 = 0
    public var puk0RemainingTries: UInt8 = 0
    public var pin1RemainingTries: UInt8 = 0
    public var puk1RemainingTries: UInt8 = 0
    public var protocolVersion: UInt16 = 0
    

    public init(rapdu: APDUResponse) throws {
        
        if rapdu.sw==0x9000 {
            
            let data = rapdu.data
            protocolMajorVersion = data[0]
            protocolMinorVersion = data[1]
            appletMajorVersion = data[2]
            appletMinorVersion = data[3]
            protocolVersion = UInt16(protocolMajorVersion<<8) + UInt16(protocolMinorVersion)
                  
            if data.count >= 8 {
                pin0RemainingTries = data[4]
                puk0RemainingTries = data[5]
                pin1RemainingTries = data[6]
                puk1RemainingTries = data[7]
                needs2FA = false //default value
            }
            if data.count >= 9 {
                needs2FA = (data[8]==0x00 ? false : true)
            }
            if data.count >= 10 {
                isSeeded = (data[9]==0x00 ? false : true)
            }
            if data.count >= 11 {
                setupDone = (data[10]==0x00 ? false : true)
            } else {
                setupDone = true
            }
            if data.count >= 12 {
                needsSecureChannel = (data[11]==0x00 ? false : true)
            } else {
                needsSecureChannel = false
                needs2FA = false //default value
            }
        } else if rapdu.sw==0x9c04 {
            setupDone = false
            isSeeded = false
            needsSecureChannel = false
        } else {
            //throws IllegalArgumentException("Wrong getStatus data!"); // should not happen
        }
    }

    public func toString() -> String {
        let status_info: String =   "setup_done: \(setupDone) \n" +
                                    "is_seeded: \(isSeeded) \n" +
                                    "needs_2FA: \(needs2FA) \n" +
                                    "needs_secure_channel: \(needsSecureChannel) \n" +
                                    "protocol_major_version: \(protocolMajorVersion) \n" +
                                    "protocol_minor_version: \(protocolMinorVersion) \n" +
                                    "applet_major_version: \(appletMajorVersion) \n" +
                                    "applet_minor_version: \(appletMinorVersion)"
        return status_info
    }
    
}

