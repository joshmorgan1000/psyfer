/**
 * @file ed25519_cryptokit.swift
 * @brief Swift wrapper around CryptoKit's Ed25519 implementation
 */

import Foundation
import CryptoKit

/**
 * @brief Generate Ed25519 key pair using CryptoKit
 */
@_cdecl("ed25519_cryptokit_generate_key_pair")
public func ed25519GenerateKeyPair(
    _ privateKey: UnsafeMutablePointer<UInt8>,
    _ publicKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let key = Curve25519.Signing.PrivateKey()
    let rawPrivKey = key.rawRepresentation
    let rawPubKey = key.publicKey.rawRepresentation
    
    rawPrivKey.withUnsafeBytes { bytes in
        privateKey.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
    }
    
    rawPubKey.withUnsafeBytes { bytes in
        publicKey.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
    }
    
    return 0
}

/**
 * @brief Generate Ed25519 key pair from seed using CryptoKit
 */
@_cdecl("ed25519_cryptokit_key_pair_from_seed")
public func ed25519KeyPairFromSeed(
    _ seed: UnsafePointer<UInt8>,
    _ privateKey: UnsafeMutablePointer<UInt8>,
    _ publicKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        let seedData = Data(bytes: seed, count: 32)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seedData)
        let rawPrivKey = key.rawRepresentation
        let rawPubKey = key.publicKey.rawRepresentation
        
        rawPrivKey.withUnsafeBytes { bytes in
            privateKey.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }
        
        rawPubKey.withUnsafeBytes { bytes in
            publicKey.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }
        
        return 0
    } catch {
        return -1
    }
}

/**
 * @brief Derive public key from private key using CryptoKit
 */
@_cdecl("ed25519_cryptokit_public_key_from_private")
public func ed25519PublicKeyFromPrivate(
    _ privateKey: UnsafePointer<UInt8>,
    _ publicKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        let privateKeyData = Data(bytes: privateKey, count: 32)
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
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
 * @brief Sign message using Ed25519
 */
@_cdecl("ed25519_cryptokit_sign")
public func ed25519Sign(
    _ message: UnsafePointer<UInt8>,
    _ messageLen: Int,
    _ privateKey: UnsafePointer<UInt8>,
    _ signature: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        let privateKeyData = Data(bytes: privateKey, count: 32)
        let messageData = Data(bytes: message, count: messageLen)
        
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        let sig = try key.signature(for: messageData)
        
        sig.withUnsafeBytes { bytes in
            signature.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 64)
        }
        
        return 0
    } catch {
        return -1
    }
}

/**
 * @brief Verify Ed25519 signature
 */
@_cdecl("ed25519_cryptokit_verify")
public func ed25519Verify(
    _ message: UnsafePointer<UInt8>,
    _ messageLen: Int,
    _ signature: UnsafePointer<UInt8>,
    _ publicKey: UnsafePointer<UInt8>
) -> Bool {
    do {
        let publicKeyData = Data(bytes: publicKey, count: 32)
        let messageData = Data(bytes: message, count: messageLen)
        let signatureData = Data(bytes: signature, count: 64)
        
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        return key.isValidSignature(signatureData, for: messageData)
    } catch {
        return false
    }
}

/**
 * @brief Check if CryptoKit Ed25519 is available
 */
@_cdecl("ed25519_cryptokit_available")
public func ed25519CryptoKitAvailable() -> Bool {
    if #available(macOS 10.15, iOS 13.0, *) {
        return true
    }
    return false
}