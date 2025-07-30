/**
 * @file 05_digital_signatures.cpp
 * @brief Ed25519 digital signature examples
 * 
 * This example demonstrates:
 * - Generating Ed25519 key pairs
 * - Signing messages
 * - Verifying signatures
 * - Batch verification
 * - Signature use cases
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <chrono>

using namespace psyfer;

/**
 * @brief Helper to print signatures and keys
 */
void print_hex(const std::string& label, std::span<const std::byte> data, size_t max_bytes = 16) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), max_bytes); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(static_cast<uint8_t>(data[i]));
    }
    if (data.size() > max_bytes) std::cout << "...";
    std::cout << std::dec << "\n";
}

/**
 * @brief Example 1: Basic signing and verification
 */
void example_basic_signing() {
    std::cout << "\n=== Example 1: Basic Ed25519 Signatures ===\n";
    
    // Generate a key pair
    auto keypair_result = crypto::ed25519::generate_key_pair();
    if (!keypair_result) {
        std::cerr << "Failed to generate key pair\n";
        return;
    }
    auto keypair = std::move(keypair_result.value());
    
    print_hex("Private key", keypair.private_key);
    print_hex("Public key", keypair.public_key);
    
    // Sign a message
    std::string message = "I hereby authorize this transaction.";
    std::vector<std::byte> msg_bytes(
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data() + message.size())
    );
    
    std::array<std::byte, 64> signature;
    auto err = crypto::ed25519::sign(msg_bytes, keypair.private_key, signature);
    if (err) {
        std::cerr << "Signing failed: " << err.message() << "\n";
        return;
    }
    
    std::cout << "\nMessage: \"" << message << "\"\n";
    print_hex("Signature", signature, 32);
    
    // Verify the signature
    bool valid = crypto::ed25519::verify(msg_bytes, signature, keypair.public_key);
    std::cout << "\nSignature verification: " << (valid ? "✅ VALID" : "❌ INVALID") << "\n";
    
    // Try to verify with wrong message
    std::string wrong_message = "I hereby authorize this fraudulent transaction.";
    std::vector<std::byte> wrong_bytes(
        reinterpret_cast<const std::byte*>(wrong_message.data()),
        reinterpret_cast<const std::byte*>(wrong_message.data() + wrong_message.size())
    );
    
    bool wrong_valid = crypto::ed25519::verify(wrong_bytes, signature, keypair.public_key);
    std::cout << "Wrong message verification: " << (wrong_valid ? "❌ VALID" : "✅ INVALID") << "\n";
    
    // Try to verify with wrong public key
    auto other_keypair = crypto::ed25519::generate_key_pair();
    if (other_keypair) {
        bool wrong_key_valid = crypto::ed25519::verify(msg_bytes, signature, other_keypair->public_key);
        std::cout << "Wrong key verification: " << (wrong_key_valid ? "❌ VALID" : "✅ INVALID") << "\n";
    }
}

/**
 * @brief Example 2: Document signing workflow
 */
void example_document_signing() {
    std::cout << "\n=== Example 2: Document Signing Workflow ===\n";
    
    // Generate signer's key pair
    auto signer_kp = crypto::ed25519::generate_key_pair();
    if (!signer_kp) return;
    
    // Simulate a document with metadata
    struct Document {
        std::string title;
        std::string author;
        std::string content;
        std::string timestamp;
        
        std::vector<std::byte> serialize() const {
            std::string combined = title + "|" + author + "|" + content + "|" + timestamp;
            return std::vector<std::byte>(reinterpret_cast<const std::byte*>(combined.data()), reinterpret_cast<const std::byte*>(combined.data() + combined.size()));
        }
    };
    
    Document doc{
        "Contract Agreement",
        "Alice Smith",
        "This agreement establishes the terms and conditions...",
        "2024-01-15T10:30:00Z"
    };
    
    std::cout << "Document:\n";
    std::cout << "  Title: " << doc.title << "\n";
    std::cout << "  Author: " << doc.author << "\n";
    std::cout << "  Content: " << doc.content.substr(0, 40) << "...\n";
    std::cout << "  Timestamp: " << doc.timestamp << "\n";
    
    // Sign the document
    auto doc_bytes = doc.serialize();
    std::array<std::byte, 64> doc_signature;
    
    crypto::ed25519::sign(doc_bytes, signer_kp->private_key, doc_signature);
    
    print_hex("\nDocument signature", doc_signature, 32);
    print_hex("Signer's public key", signer_kp->public_key);
    
    // Verification (by another party)
    std::cout << "\nVerification process:\n";
    bool verified = crypto::ed25519::verify(doc_bytes, doc_signature, signer_kp->public_key);
    std::cout << "  Document integrity: " << (verified ? "✅ VERIFIED" : "❌ FAILED") << "\n";
    
    // Simulate tampering
    doc.content += " (modified)";
    auto tampered_bytes = doc.serialize();
    bool tampered_check = crypto::ed25519::verify(tampered_bytes, doc_signature, signer_kp->public_key);
    std::cout << "  Tampered document: " << (tampered_check ? "❌ VERIFIED" : "✅ REJECTED") << "\n";
}

/**
 * @brief Example 3: Multi-signature scenario
 */
void example_multi_signature() {
    std::cout << "\n=== Example 3: Multi-Signature Scenario ===\n";
    
    // Create multiple signers
    struct Signer {
        std::string name;
        crypto::ed25519::key_pair keypair;
        std::array<std::byte, 64> signature;
    };
    
    std::vector<Signer> signers;
    std::vector<std::string> names = {"Alice", "Bob", "Charlie"};
    
    // Generate key pairs for all signers
    for (const auto& name : names) {
        auto kp = crypto::ed25519::generate_key_pair();
        if (!kp) continue;
        signers.push_back({name, std::move(*kp), {}});
    }
    
    // Document to be signed by all
    std::string document = "Multi-party agreement requiring all signatures";
    std::vector<std::byte> doc_bytes(
        reinterpret_cast<const std::byte*>(document.data()),
        reinterpret_cast<const std::byte*>(document.data() + document.size())
    );
    
    std::cout << "Document: \"" << document << "\"\n";
    std::cout << "\nSigners:\n";
    
    // Each party signs
    for (auto& signer : signers) {
        crypto::ed25519::sign(doc_bytes, signer.keypair.private_key, signer.signature);
        std::cout << "  " << signer.name << ":\n";
        print_hex("    Public key", signer.keypair.public_key);
        print_hex("    Signature", signer.signature, 16);
    }
    
    // Verify all signatures
    std::cout << "\nVerification:\n";
    int valid_count = 0;
    
    for (const auto& signer : signers) {
        bool valid = crypto::ed25519::verify(doc_bytes, signer.signature, signer.keypair.public_key);
        std::cout << "  " << signer.name << ": " << (valid ? "✅" : "❌") << "\n";
        if (valid) valid_count++;
    }
    
    std::cout << "\nValid signatures: " << valid_count << "/" << signers.size() << "\n";
    std::cout << "All required signatures present: " 
              << (valid_count == signers.size() ? "✅" : "❌") << "\n";
}

/**
 * @brief Example 4: Performance benchmarks
 */
void example_performance() {
    std::cout << "\n=== Example 4: Ed25519 Performance ===\n";
    
    const int iterations = 100;
    
    // Generate test keypair
    auto keypair = crypto::ed25519::generate_key_pair();
    if (!keypair) return;
    
    // Test data
    std::string message = "Performance test message for Ed25519 signatures";
    std::vector<std::byte> msg_bytes(
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data() + message.size())
    );
    std::array<std::byte, 64> signature;
    
    // Benchmark key generation
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto kp = crypto::ed25519::generate_key_pair();
        if (!kp) break;
    }
    
    auto keygen_time = std::chrono::high_resolution_clock::now() - start;
    
    // Benchmark signing
    start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        crypto::ed25519::sign(msg_bytes, keypair->private_key, signature);
    }
    
    auto sign_time = std::chrono::high_resolution_clock::now() - start;
    
    // Benchmark verification
    crypto::ed25519::sign(msg_bytes, keypair->private_key, signature);
    
    start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        crypto::ed25519::verify(msg_bytes, signature, keypair->public_key);
    }
    
    auto verify_time = std::chrono::high_resolution_clock::now() - start;
    
    // Calculate operations per second
    double keygen_per_sec = iterations / std::chrono::duration<double>(keygen_time).count();
    double sign_per_sec = iterations / std::chrono::duration<double>(sign_time).count();
    double verify_per_sec = iterations / std::chrono::duration<double>(verify_time).count();
    
    std::cout << "Operations (" << iterations << " iterations):\n";
    std::cout << "  Key generation: " << std::fixed << std::setprecision(0) 
              << keygen_per_sec << " ops/sec\n";
    std::cout << "  Signing:        " << sign_per_sec << " ops/sec\n";
    std::cout << "  Verification:   " << verify_per_sec << " ops/sec\n";
    
    std::cout << "\nAverage times:\n";
    std::cout << "  Key generation: " << std::setprecision(3) 
              << (1000.0 / keygen_per_sec) << " ms\n";
    std::cout << "  Signing:        " << (1000.0 / sign_per_sec) << " ms\n";
    std::cout << "  Verification:   " << (1000.0 / verify_per_sec) << " ms\n";
    
    // Check if hardware acceleration is available
    std::cout << "\nHardware acceleration: " 
              << (crypto::ed25519::hardware_accelerated() ? "✅ AVAILABLE" : "❌ NOT AVAILABLE") << "\n";
}

/**
 * @brief Example 5: Deterministic signatures
 */
void example_deterministic_signatures() {
    std::cout << "\n=== Example 5: Deterministic Signatures ===\n";
    
    // Generate key pair
    auto keypair = crypto::ed25519::generate_key_pair();
    if (!keypair) return;
    
    std::string message = "Test message for deterministic signatures";
    std::vector<std::byte> msg_bytes(
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data() + message.size())
    );
    
    // Sign the same message multiple times
    std::cout << "Signing the same message 3 times:\n";
    std::vector<std::array<std::byte, 64>> signatures;
    
    for (int i = 0; i < 3; ++i) {
        std::array<std::byte, 64> sig;
        crypto::ed25519::sign(msg_bytes, keypair->private_key, sig);
        signatures.push_back(sig);
        
        std::cout << "  Signature " << (i + 1) << ": ";
        for (size_t j = 0; j < 8; ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(static_cast<uint8_t>(sig[j]));
        }
        std::cout << "...\n";
    }
    
    // Check if signatures are identical (Ed25519 is deterministic)
    std::cout << "\nSignature comparison:\n";
    bool all_same = true;
    for (size_t i = 1; i < signatures.size(); ++i) {
        bool same = (signatures[i] == signatures[0]);
        std::cout << "  Signature 1 == Signature " << (i + 1) << ": " 
                  << (same ? "✅" : "❌") << "\n";
        all_same &= same;
    }
    
    std::cout << "\nAll signatures identical: " << (all_same ? "✅" : "❌") << "\n";
    std::cout << "Ed25519 produces deterministic signatures.\n";
}

/**
 * @brief Example 6: Batch signature verification
 */
void example_batch_verification() {
    std::cout << "\n=== Example 6: Batch Signature Operations ===\n";
    
    const size_t num_messages = 10;
    
    struct SignedMessage {
        std::string content;
        crypto::ed25519::key_pair signer;
        std::array<std::byte, 64> signature;
    };
    
    std::vector<SignedMessage> messages;
    
    // Create and sign multiple messages
    std::cout << "Creating " << num_messages << " signed messages...\n";
    
    for (size_t i = 0; i < num_messages; ++i) {
        auto kp = crypto::ed25519::generate_key_pair();
        if (!kp) continue;
        
        SignedMessage msg;
        msg.content = "Message #" + std::to_string(i) + " from sender";
        msg.signer = std::move(*kp);
        
        std::vector<std::byte> msg_bytes(
        reinterpret_cast<const std::byte*>(msg.content.data()),
        reinterpret_cast<const std::byte*>(msg.content.data() + msg.content.size())
    );
        crypto::ed25519::sign(msg_bytes, msg.signer.private_key, msg.signature);
        
        messages.push_back(std::move(msg));
    }
    
    // Verify all signatures
    auto start = std::chrono::high_resolution_clock::now();
    size_t valid_count = 0;
    
    for (const auto& msg : messages) {
        std::vector<std::byte> msg_bytes(
        reinterpret_cast<const std::byte*>(msg.content.data()),
        reinterpret_cast<const std::byte*>(msg.content.data() + msg.content.size())
    );
        if (crypto::ed25519::verify(msg_bytes, msg.signature, msg.signer.public_key)) {
            valid_count++;
        }
    }
    
    auto verify_time = std::chrono::high_resolution_clock::now() - start;
    
    std::cout << "\nBatch verification results:\n";
    std::cout << "  Total messages:    " << messages.size() << "\n";
    std::cout << "  Valid signatures:  " << valid_count << "\n";
    std::cout << "  Invalid signatures: " << (messages.size() - valid_count) << "\n";
    std::cout << "  Total time:        " << std::fixed << std::setprecision(3)
              << std::chrono::duration<double, std::milli>(verify_time).count() << " ms\n";
    std::cout << "  Time per verify:   " 
              << (std::chrono::duration<double, std::milli>(verify_time).count() / messages.size()) 
              << " ms\n";
}

int main() {
    std::cout << "Psyfer Ed25519 Digital Signature Examples\n";
    std::cout << "=========================================\n";
    
    try {
        example_basic_signing();
        example_document_signing();
        example_multi_signature();
        example_performance();
        example_deterministic_signatures();
        example_batch_verification();
        
        std::cout << "\n✅ All digital signature examples completed successfully!\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}