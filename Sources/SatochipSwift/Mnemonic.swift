//
//  SeedkeeperUtil.swift
//
//
//  Created by Satochip on 26/04/2024.
//

import Foundation
import MnemonicSwift

public enum MnemonicError: Error {
    case mnemonicTypeNotSupported
    case wrongBip39Checksum
    case wrongBip39Word(word: String)
    case invalidBitString
    case failedToRecoverBIP39fromEntropy(recoverd: String, expected: String)
}

public enum MnemonicType: UInt8 {
    case bip39 = 0x00
    case electrum = 0x01
}

public enum MnemonicLanguage: UInt8 {
    case english = 0x00
    case japanese = 0x01
    case korean = 0x02
    case spanish = 0x03
    case chinese_simplified = 0x04
    case chinese_traditional = 0x05
    case french = 0x06
    case italian = 0x07
    case czech = 0x08
    case portuguese = 0x09
    
    
    func words() -> [String] {
        switch self {
        case .english:
            return MnemonicEnglish.words //String.englishMnemonics
        default:
            return []
        }
    }
}

// TODO: support other languages than english
public class Mnemonic {
    static let shared = Mnemonic()
    
    private init() {}
    
    public static func mnemonicString(hexString: String) throws -> String {
        let bip39 = try MnemonicSwift.Mnemonic.mnemonicString(from: hexString, language: .english)
        return bip39
    }
    
    public static func generateMnemonic(strength: Int) throws -> String {
        // todo: check strength
        let bip39 = try MnemonicSwift.Mnemonic.generateMnemonic(strength: strength, language: .english)
        return bip39
    }
    
    public static func mnemonicToMasterseed(mnemonic: String, passphrase: String = "", mnemonicType: MnemonicType = MnemonicType.bip39) throws -> [UInt8]{
        
        if mnemonicType == MnemonicType.electrum {
            throw MnemonicError.mnemonicTypeNotSupported
        }
        
        try MnemonicSwift.Mnemonic.validate(mnemonic: mnemonic)
        let masterseedBytes = try MnemonicSwift.Mnemonic.deterministicSeedBytes(from: mnemonic,
                                                                passphrase: passphrase,
                                                                language: .english)
        return masterseedBytes
    }
    
    public static func mnemonicToEntropy(bip39: String) throws -> [UInt8] {
        try MnemonicSwift.Mnemonic.validate(mnemonic: bip39)
        //print("[mnemonicToEntropy] bip39: \(bip39)")
              
        // split mnemonic in words
        let words = bip39.components(separatedBy: " ")
        //print("[mnemonicToEntropy] words: \(words)")
        
        // get the position in the wordbook for each bip39 word
        let wordbook = MnemonicLanguage.english.words() //MnemonicLanguageType.english.words()
        //var indexes = [Int](repeating: 0, count: words.count)
        var bip39Bitstring = [String]()
        for index in 0..<words.count {
            //print("[mnemonicToEntropy] index: \(index)")
            let word = words[index]
            guard let pos = wordbook.firstIndex(of: word) else {
                throw MnemonicError.wrongBip39Word(word: word)
            }
            //print("[mnemonicToEntropy] pos: \(pos)")
            let pos0 = UInt8(pos%256)
            let pos1 = UInt8((pos>>8)%256)
            var posBitstring =  pos1.mnemonicBits() + pos0.mnemonicBits()
            //print("[mnemonicToEntropy] words: \(posBitstring)")
            posBitstring = Array(posBitstring[5..<16])
            //print("[mnemonicToEntropy] words: \(posBitstring)")
            bip39Bitstring += posBitstring
            //print("-------------------")
        }
        //print("[mnemonicToEntropy] bip39Bitstring: \(bip39Bitstring)")
              
        //
        let bip39BitstringLengthBits = bip39Bitstring.count
        //let bip39BitstringLengthBytes = bip39BitstringLengthBits/8
        //print("[mnemonicToEntropy] bip39BitstringLengthBits: \(bip39BitstringLengthBits)")
        //print("[mnemonicToEntropy] bip39BitstringLengthBytes: \(bip39BitstringLengthBytes)")
        
        // separate checksum from actual entropy
        let checksumLengthBits = bip39Bitstring.count/33 //33
        //print("[mnemonicToEntropy] checksumLengthBits: \(checksumLengthBits)")
        let entropyLengthBits = bip39Bitstring.count - checksumLengthBits
        let entropyLengthBytes = entropyLengthBits/8
        //print("[mnemonicToEntropy] entropyLengthBits: \(entropyLengthBits)")
        //print("[mnemonicToEntropy] entropyLengthBytes: \(entropyLengthBytes)")
        
        // convert entropy to bytes
        var entropyBytes = [UInt8](repeating: 0, count: entropyLengthBytes)
        for index in 0..<entropyLengthBytes {
            let bits = Array(bip39Bitstring[(index*8)..<(index*8+8)])
            guard let byte = UInt8(bits.joined(separator: ""), radix: 2) else {
                throw MnemonicError.invalidBitString
            }
            entropyBytes[index] = byte
        }
        //print("[mnemonicToEntropy] entropyBytes: \(entropyBytes.bytesToHex)")
        
        // validate entropy
        let bip39Recovered = try MnemonicSwift.Mnemonic.mnemonicString(from: entropyBytes.bytesToHex, language: .english)
        //print("[mnemonicToEntropy] bip39Recovered: \(bip39Recovered)")
        if (bip39Recovered != bip39){
            throw MnemonicError.failedToRecoverBIP39fromEntropy(recoverd: bip39Recovered, expected: bip39)
        }
        
        // compute checksum from entropy
        let hashByte = Crypto.shared.sha256(entropyBytes)
        //let fullChecksumBits = hashByte.toBitArray() //debug
        //print("[mnemonicToEntropy] fullChecksumBits: \(fullChecksumBits)")
        let recoveredChecksumBits = Array(hashByte.toBitArray()[0..<checksumLengthBits])
        //print("[mnemonicToEntropy] recoveredChecksumBits: \(recoveredChecksumBits)")
        let expectedChecksumBits = Array(bip39Bitstring[entropyLengthBits..<bip39BitstringLengthBits])
        //print("[mnemonicToEntropy] expectedChecksumBits: \(expectedChecksumBits)")
        if (recoveredChecksumBits != expectedChecksumBits){
            throw MnemonicError.wrongBip39Checksum
        }
        
        return entropyBytes
    }
    
    public static func entropyToMnemonic(entropy: [UInt8]) throws -> String {
        let entropyHex = entropy.bytesToHex
        let mnemonic = try MnemonicSwift.Mnemonic.mnemonicString(from: entropyHex, language: .english)
        return mnemonic
    }
    
}
