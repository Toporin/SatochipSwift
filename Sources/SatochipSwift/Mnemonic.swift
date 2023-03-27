import Foundation

public class Mnemonic {
    static let bip39IterationCount = 2048
    
    public static func toBinarySeed(mnemonicPhrase: String, password: String = "") -> [UInt8] {
        Crypto.shared.pbkdf2(password: mnemonicPhrase,
                             salt: Array(("mnemonic" + password).utf8),
                             iterations: Mnemonic.bip39IterationCount,
                             hmac: PBKDF2HMac.sha512)
    }
    
    public let indexes: [UInt16]
    public var words: [String] {
        get {
            precondition(wordList != nil)
            return self.indexes.map { (idx) -> String in
                self.wordList![Int(idx)]
            }
        }
    }
    
    public var wordList: [String]?
    
    public init(rawData: [UInt8]) {
        var idx: [UInt16] = []
        
        for i in 0..<(rawData.count / 2) {
            idx.append((UInt16(rawData[i * 2]) << 8) | UInt16(rawData[(i * 2) + 1]))
        }
        
        self.indexes = idx
    }
    
    public func useBIP39EnglishWordlist() {
        self.wordList = MnemonicEnglish.words
    }
    
    public func toMnemonicPhrase() -> String {
        self.words.joined(separator: " ")
    }
    
    public func toBinarySeed(password: String = "") -> [UInt8] {
        Mnemonic.toBinarySeed(mnemonicPhrase: toMnemonicPhrase(), password: password)
    }
    
    public func toBIP32KeyPair(password: String = "") -> BIP32KeyPair {
        BIP32KeyPair(fromSeed: toBinarySeed(password: password))
    }
}
