/**
 * @file x25519_cryptokit.swift
 * @brief Swift wrapper around CryptoKit's X25519 implementation
 */

import Foundation
import CryptoKit

/**
 * @brief Generate X25519 private key using CryptoKit
 */
@_cdecl("x25519_cryptokit_generate_private_key")
public func x25519GeneratePrivateKey(_ privateKey: UnsafeMutablePointer<UInt8>) -> Int32 {
    let key = Curve25519.KeyAgreement.PrivateKey()
    let rawKey = key.rawRepresentation
    
    rawKey.withUnsafeBytes { bytes in
        privateKey.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
    }
    
    return 0
}

/**
 * @brief Derive public key from private key using CryptoKit
 */
@_cdecl("x25519_cryptokit_derive_public_key")
public func x25519DerivePublicKey(
    _ privateKey: UnsafePointer<UInt8>,
    _ publicKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        let privateKeyData = Data(bytes: privateKey, count: 32)
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        let pubKey = key.publicKey.rawRepresentation
        
        pubKey.withUnsafeBytes { bytes in
            publicKey.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }
        
        return 0
    } catch {
        return -1
    }
}

/**
 * @brief Compute shared secret using CryptoKit
 */
@_cdecl("x25519_cryptokit_compute_shared_secret")
public func x25519ComputeSharedSecret(
    _ privateKey: UnsafePointer<UInt8>,
    _ peerPublicKey: UnsafePointer<UInt8>,
    _ sharedSecret: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        let privateKeyData = Data(bytes: privateKey, count: 32)
        let publicKeyData = Data(bytes: peerPublicKey, count: 32)
        
        let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
        
        let secret = try privKey.sharedSecretFromKeyAgreement(with: pubKey)
        
        secret.withUnsafeBytes { bytes in
            sharedSecret.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }
        
        return 0
    } catch {
        return -1
    }
}

/**
 * @brief Check if CryptoKit is available
 */
@_cdecl("x25519_cryptokit_available")
public func x25519CryptoKitAvailable() -> Bool {
    if #available(macOS 10.15, iOS 13.0, *) {
        return true
    }
    return false
}