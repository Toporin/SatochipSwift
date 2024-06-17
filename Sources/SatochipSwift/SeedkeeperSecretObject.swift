//
//  File.swift
//  
//
//  Created by Satochip on 18/04/2024.
//

import Foundation

public struct SeedkeeperSecretEncryptedParams {
    var sidPubkey: Int = 0
    var iv: [UInt8] = []
    var hmac: [UInt8] = []
    //var fingerprint: [UInt8] = []
}

public struct SeedkeeperSecretObject {
    
    public var secretBytes: [UInt8] = []
    public var secretHeader: SeedkeeperSecretHeader
    public var isEncrypted: Bool = false
    public var secretEncryptedParams: SeedkeeperSecretEncryptedParams? = nil
    
    public init(secretBytes: [UInt8] = [],
                secretHeader: SeedkeeperSecretHeader,
                isEncrypted: Bool = false,
                secretEncryptedParams: SeedkeeperSecretEncryptedParams? = nil) {
        self.secretBytes = secretBytes
        self.secretHeader = secretHeader
        self.isEncrypted = isEncrypted
        self.secretEncryptedParams = secretEncryptedParams
    }
    
    public func getSidPubKey() -> Int? {
        if let secretEncryptedParams = secretEncryptedParams {
            return secretEncryptedParams.sidPubkey
        }
        return nil
    }
    
    public func getSecretEncryptedParams() -> SeedkeeperSecretEncryptedParams? {
        return secretEncryptedParams
    }
    
    public func getFingerprintFromSecret() -> [UInt8]{
        if isEncrypted {
            // we can't compute fingerprint from secret since it is encrypted
            //return [UInt8]()
            return secretHeader.fingerprintBytes
        }
        let secretHash = Crypto.shared.sha256(secretBytes)
        let fingerprintFromSecret = Array(secretHash[0..<4])
        return fingerprintFromSecret
    }
    
    // todo: this method only makes sense for entropy secret
    public func getSha512FromSecret() -> [UInt8]{
        if isEncrypted {
            return [UInt8]()
        }
        let secretHash = Crypto.shared.sha512(Array(secretBytes[1..<secretBytes.count]))
        return secretHash
    }
    
    // todo: this method only makes sense for Master Password secret
    public func getHmacSha512(salt: [UInt8]) -> [UInt8] {
        if isEncrypted {
            return [UInt8]()
        }
        let hmac = Crypto.shared.hmacSHA512(data: Array(secretBytes[1..<secretBytes.count]), key: salt)
        return hmac
    }
    
}
