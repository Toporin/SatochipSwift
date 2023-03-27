public enum StatusWord: UInt16, Error {
    // generic
    case ok = 0x9000
    case cardNotPresent = 0x0000
    case unknownError = 0x6F00
    case commandUnsupported = 0x6D00
    case wrongPINMask = 0x63C0 // includes number of tries remaining in last nibble
    case wrongPINLegacy = 0x9C02 // DEPRECATED - Entered PIN is not correct
    case operationNotAllowed = 0x9C03 // Required operation is not allowed in actual circumstances
    case setupNotDone = 0x9C04 // Required setup is not not done
    case setupAlreadyDone = 0x9C07 // Required setup is already done
    case unsupportedFeature = 0x9C05 // Required feature is not (yet) supported
    case unauthorized = 0x9C06 // Required operation was not authorized because of a lack of privileges
    case incorrectAlg = 0x9C09 // Algorithm specified is not correct
    case noMemoryLeft = 0x9C01 // There have been memory problems on the card
    
    // globalplatform
    case referencedDataNotFound = 0x6A88
    
    //case swObjectNotFound = 0x9C07 // DEPRECATED - Required object is missing
    case incorrectP1 = 0x9C10 // Incorrect P1 parameter
    case incorrectP2 = 0x9C11 // Incorrect P2 parameter
    case incorrectInitialization = 0x9C13 // Incorrect initialization of method
    case invalidParameter = 0x9C0F // Invalid input parameter to command
    case signatureInvalid = 0x9C0B // Verify operation detected an invalid signature
    case identityBlocked = 0x9C0C // Operation has been blocked for security reason
    case hmacUnupportedKeySize = 0x9C1E // HMAC error
    case hmacUnupportedMsgSize = 0x9C1F // HMAC error
    case internalError = 0x9CFF // for debugging purposes
    case pkiAlreadyLocked = 0x9C40 // PKI perso error
    case resetToFactory = 0xFF00 // Card has been reset to factory
    case insDeprecated = 0x9C26 // For instructions that have been deprecated
    case debugFlag = 0x9FFF // for debugging purpose 2

    // secure channel
    case secureChannelRequired = 0x9C20
    case secureChannelUninitialized = 0x9C21
    case secureChannelIncorrectIV = 0x9C22
    case secureChannelIncorrectMac = 0x9C23
    
    // satochip
    case ecKeysInitializedKey = 0x9C1A // Eckeys already initialized
    case bip32DerivationError = 0x9C0E // Very low probability error
    case bip32UninitializedSeed = 0x9C14 // Bip32 seed is not initialized
    case bip32InitializedSeed = 0x9C17 // Bip32 seed is already initialized (must be reset before change)
    case bip32UninitializedAuthentikey = 0x9C16 // DEPRECATED - Bip32 authentikey pubkey is not initialized
    case incorrectTxHash = 0x9C15 // Incorrect transaction hash
    case secondFactorInitialized = 0x9C18 // 2FA already initialized
    case secondFactorUninitialized = 0x9C19 // 2FA uninitialized
    
    // secure import
    case secureImportDataTooLong = 0x9C32 // Secret data is too long for import
    case secureImportIncorrectMac = 0x9C33 // Wrong HMAC when importing Secret through Secure import
    case secureImportIncorrectFingerprint = 0x9C34 // Wrong Fingerprint when importing Secret through Secure import
    case secureImportNoTrustePubkey = 0x9C35 // No Trusted Pubkey when importing Secret through Secure import
    
    // Satodime
    
    // seedkeeeper
    
}

