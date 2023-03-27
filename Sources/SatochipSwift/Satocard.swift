
public enum CLA: UInt8 {
    case iso7816 = 0x00
    case proprietary = 0xB0
    //case proprietary = 0x80
}

public enum ISO7816INS: UInt8 {
    case select = 0xa4
}

public enum SatocardINS: UInt8 {
    case setup = 0x2A
    //resetToFactorySettings
    case resetToFactory = 0xFf
    // External authentication
    case verifyPin = 0x42
    case changePin = 0x44
    case unblockPin = 0x46
    // Status information
    case listPins = 0x48
    case getStatus = 0x3C
    case cardLabel = 0x3D
    //secureChannel
    case initSecureChannel = 0x81
    case processSecureChannel = 0x82
    //hdWallet
    case bip32ImportSeed = 0x6C
    case bip32ResetSeed = 0x77
    case bip32GetAuthentikey = 0x73
    case bip32SetAuthentikeyPubkey = 0x75
    case bip32GetExtendedKey = 0x6D
    case bip32SetExtendedPubkey = 0x74
    // satochip card
    case signMessage = 0x6E
    case signShortMessage = 0x72
    case signTransaction = 0x6F
    case parseTransaction = 0x71
    case cryptTransaction2Fa = 0x76
    case set2FaKey = 0x79
    case reset2FaKey = 0x78
    case signTransactionHash = 0x7A
    //secureImportFromSeedKeeper
    case importEncryptedSecret = 0xAc
    case importTrustedPubkey = 0xAa
    case exportTrustedPubkey = 0xAb
    case exportAuthentikey = 0xAd
    //personalizationPkiSupport
    case importPkiCertificate = 0x92
    case exportPkiCertificate = 0x93
    case signPkiCsr = 0x94
    case exportPkiPubkey = 0x98
    case lockPki = 0x99
    case challengeResponsePki = 0x9A
    //satodime
    case getSatodimeStatus = 0x50
    case getSatodimeKeyslotStatus = 0x51
    case setSatodimeKeyslotStatus = 0x52
    case getSatodimePubkey = 0x55 // DoNotChangeState
    case getSatodimePrivkey = 0x56 // DoNotChangeState
    case sealSatodimeKey = 0x57 //ChangeKeyStateFromUninitializedToSealed
    case unsealSatodimeKey = 0x58 //ChangeKeyStateFromSealedToUnsealed
    case resetSatodimeKey = 0x59 //ChangeKeyStateFromUnsealedToUninitialized
    case initiateSatodimeTransfer = 0x5A
    // seedkeeper
}

struct SatocardCst {
    // generic
    static let sizeECPrivkey = 32
    static let sizeECPubkey = 65
    static let sizeECPubkeyComp = 33
    static let sizeECCoordx = 32
    // satochip
    
    // satodime
    static let sizeUnlockCounter = 4
    static let sizeUnlockSecret = 20
    static let sizeUnlockCode = 20
    static let sizeSlip44 = 4
    static let sizeContract = 2+32
    static let sizeTokenid = 2+32
    static let sizeData = 2+64
    static let sizeEntropy = 32
}

public enum SatocardIdentifier: String {
    case satochipAID = "5361746f43686970" //SatoChip
    case seedkeeperAID = "536565644b6565706572" //SeedKeeper
    case satodimeAID = "5361746f44696d65" //SatoDime
    
    public var bytesValue: [UInt8] {
        return rawValue.hexToBytes
    }
}

