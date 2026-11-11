
public struct CardStatus {

    public var setupDone: Bool = false
    public var isSeeded: Bool = false
    public var needsSecureChannel: Bool = false
    public var needs2FA: Bool = false
    public private(set) var supportsTaproot: Bool = false
    public private(set) var supportsTaprootMultisig: Bool = false
    public var protocolMajorVersion: UInt8 = 0
    public var protocolMinorVersion: UInt8 = 0
    public var appletMajorVersion: UInt8 = 0
    public var appletMinorVersion: UInt8 = 0
    public var pin0RemainingTries: UInt8 = 0
    public var puk0RemainingTries: UInt8 = 0
    public var pin1RemainingTries: UInt8 = 0
    public var puk1RemainingTries: UInt8 = 0
    public var protocolVersion: UInt16 = 0
    

    public init?(rapdu: APDUResponse) {
        
        if (rapdu.sw == 0x9000) && (rapdu.data.count >= 4) {
            
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
            }

            let version = (UInt32(data[0]) << 24) | (UInt32(data[1]) << 16)
                | (UInt32(data[2]) << 8) | UInt32(data[3])
            // Policies: Schnorr at 13 (since 0.14-0.5), MuSig2 at 16; 0 = enabled.
            let schnorrEnabled = version < 0x000e0005
                || (data.count >= 16 && data[13] == 0)
            supportsTaproot = data.count >= 12 && version >= 0x000e0001
                && schnorrEnabled
            // Require 0.15-0.1's protection against encrypted nonce replay.
            supportsTaprootMultisig = supportsTaproot && version >= 0x000f0001
                && data.count >= 17 && data[16] == 0
        } else if rapdu.sw==0x9c04 {
            setupDone = false
            isSeeded = false
            needsSecureChannel = false
        } else {
            // NOTE: this is a breaking change compared to v0.1.0
            return nil
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

