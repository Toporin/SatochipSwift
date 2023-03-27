import Foundation

public enum SecureChannelError: Error {
    case wrongEncryptedResponseLength(length: Int)
}

public enum CardError: Error {
    case wrongPIN(retryCounter: Int)
    case unrecoverableSignature
    case invalidState
    case notPaired
    case pinBlocked
    case invalidAuthData
    case invalidMac
    case communicationError
    // generic
    case setupAlreadyDone
    case setupNotDone
    case cardNotPresent
    case CommandUnsupported(sw: UInt16)
    // satochip
    case wrongPINLegacy
    // satodime
    
    
    // seedkeeper
}

extension CardError: Equatable {

    public static func ==(lhs: CardError, rhs: CardError) -> Bool {
        switch (lhs, rhs) {
        case (.wrongPIN(let lattempt), .wrongPIN(let rattempt)): return lattempt == rattempt
        case (.unrecoverableSignature, .unrecoverableSignature),
             (.invalidState, .invalidState),
             (.notPaired, .notPaired),
             (.pinBlocked, .pinBlocked),
             (.invalidAuthData, .invalidAuthData),
             (.invalidMac, .invalidMac),
             (.communicationError, .communicationError),
             (.wrongPINLegacy, .wrongPINLegacy):
            return true
        default: return false
        }
    }

}
