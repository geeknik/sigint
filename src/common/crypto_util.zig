// Cryptographic utilities for SIGINT profile encryption and policy signing.
//
// Uses Zig std.crypto exclusively:
// - AES-256-GCM for profile encryption at rest
// - Ed25519 for policy file signing/verification
// - Random nonce/salt generation via std.crypto.random
// - Secure zeroing via std.crypto.secureZero

const std = @import("std");
const crypto = std.crypto;

/// AES-256-GCM parameters.
pub const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
pub const key_length: usize = Aes256Gcm.key_length; // 32
pub const nonce_length: usize = Aes256Gcm.nonce_length; // 12
pub const tag_length: usize = Aes256Gcm.tag_length; // 16

/// Ed25519 types.
pub const Ed25519 = crypto.sign.Ed25519;

/// Overhead added by encryption: nonce (12) + tag (16) = 28 bytes.
pub const encryption_overhead: usize = nonce_length + tag_length;

/// Encrypt data with AES-256-GCM.
/// Output format: [nonce: 12 bytes][ciphertext: N bytes][tag: 16 bytes]
/// Caller must provide output buffer of at least plaintext.len + encryption_overhead.
pub fn encrypt(plaintext: []const u8, key: *const [key_length]u8, out: []u8) error{BufferTooSmall}!usize {
    const total = plaintext.len + encryption_overhead;
    if (out.len < total) return error.BufferTooSmall;

    // Generate random nonce
    var nonce: [nonce_length]u8 = undefined;
    crypto.random.bytes(&nonce);

    // Write nonce
    @memcpy(out[0..nonce_length], &nonce);

    // Encrypt
    var tag: [tag_length]u8 = undefined;
    const ciphertext = out[nonce_length..][0..plaintext.len];
    Aes256Gcm.encrypt(ciphertext, &tag, plaintext, &.{}, nonce, key.*);

    // Write tag after ciphertext
    @memcpy(out[nonce_length + plaintext.len ..][0..tag_length], &tag);

    return total;
}

/// Decrypt data encrypted with AES-256-GCM.
/// Input format: [nonce: 12][ciphertext: N][tag: 16]
/// Returns the decrypted plaintext slice within the provided output buffer.
pub fn decrypt(ciphertext_with_meta: []const u8, key: *const [key_length]u8, out: []u8) error{ AuthenticationFailed, BufferTooSmall, InputTooShort }![]u8 {
    if (ciphertext_with_meta.len < encryption_overhead) return error.InputTooShort;

    const ciphertext_len = ciphertext_with_meta.len - encryption_overhead;
    if (out.len < ciphertext_len) return error.BufferTooSmall;

    // Extract nonce
    const nonce: [nonce_length]u8 = ciphertext_with_meta[0..nonce_length].*;

    // Extract tag
    const tag: [tag_length]u8 = ciphertext_with_meta[nonce_length + ciphertext_len ..][0..tag_length].*;

    // Decrypt
    const ciphertext = ciphertext_with_meta[nonce_length..][0..ciphertext_len];
    Aes256Gcm.decrypt(out[0..ciphertext_len], ciphertext, tag, &.{}, nonce, key.*) catch
        return error.AuthenticationFailed;

    return out[0..ciphertext_len];
}

/// Generate a new Ed25519 key pair.
pub fn generateSigningKeypair() Ed25519.KeyPair {
    return Ed25519.KeyPair.generate();
}

/// Sign a message with an Ed25519 secret key.
pub fn sign(message: []const u8, keypair: Ed25519.KeyPair) ![Ed25519.Signature.encoded_length]u8 {
    const sig = try keypair.sign(message, null);
    return sig.toBytes();
}

/// Verify an Ed25519 signature.
pub fn verify(message: []const u8, sig_bytes: *const [Ed25519.Signature.encoded_length]u8, public_key_bytes: *const [Ed25519.PublicKey.encoded_length]u8) !void {
    const sig = Ed25519.Signature.fromBytes(sig_bytes.*);
    const pk = try Ed25519.PublicKey.fromBytes(public_key_bytes.*);
    try sig.verify(message, pk);
}

/// Generate a random salt.
pub fn generateSalt(out: *[32]u8) void {
    crypto.random.bytes(out);
}

/// Securely zero a buffer.
pub fn secureZero(buf: []u8) void {
    crypto.secureZero(u8, buf);
}

// ---- Tests ----

test "AES-256-GCM encrypt/decrypt round-trip" {
    var key: [key_length]u8 = undefined;
    crypto.random.bytes(&key);
    defer crypto.secureZero(u8, &key);

    const plaintext = "SIGINT profile data - sensitive biometric";
    var encrypted: [plaintext.len + encryption_overhead]u8 = undefined;
    const enc_len = try encrypt(plaintext, &key, &encrypted);
    try std.testing.expectEqual(plaintext.len + encryption_overhead, enc_len);

    var decrypted: [plaintext.len]u8 = undefined;
    const result = try decrypt(encrypted[0..enc_len], &key, &decrypted);
    try std.testing.expect(std.mem.eql(u8, plaintext, result));
}

test "AES-256-GCM rejects wrong key" {
    var key1: [key_length]u8 = undefined;
    var key2: [key_length]u8 = undefined;
    crypto.random.bytes(&key1);
    crypto.random.bytes(&key2);

    const plaintext = "secret data";
    var encrypted: [plaintext.len + encryption_overhead]u8 = undefined;
    _ = try encrypt(plaintext, &key1, &encrypted);

    var decrypted: [plaintext.len]u8 = undefined;
    const result = decrypt(&encrypted, &key2, &decrypted);
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "AES-256-GCM rejects tampered ciphertext" {
    var key: [key_length]u8 = undefined;
    crypto.random.bytes(&key);

    const plaintext = "integrity test";
    var encrypted: [plaintext.len + encryption_overhead]u8 = undefined;
    _ = try encrypt(plaintext, &key, &encrypted);

    // Tamper with a ciphertext byte
    encrypted[nonce_length + 2] ^= 0xFF;

    var decrypted: [plaintext.len]u8 = undefined;
    const result = decrypt(&encrypted, &key, &decrypted);
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "Ed25519 sign/verify round-trip" {
    const kp = generateSigningKeypair();
    const message = "policy.toml contents here";
    const sig = try sign(message, kp);
    const pk_bytes = kp.public_key.toBytes();
    try verify(message, &sig, &pk_bytes);
}

test "Ed25519 rejects tampered message" {
    const kp = generateSigningKeypair();
    const message = "original message";
    const sig = try sign(message, kp);
    const pk_bytes = kp.public_key.toBytes();
    const tampered = "tampered message";
    const result = verify(tampered, &sig, &pk_bytes);
    try std.testing.expectError(error.SignatureVerificationFailed, result);
}

test "Ed25519 rejects wrong public key" {
    const kp1 = generateSigningKeypair();
    const kp2 = generateSigningKeypair();
    const message = "signed by kp1";
    const sig = try sign(message, kp1);
    const wrong_pk = kp2.public_key.toBytes();
    const result = verify(message, &sig, &wrong_pk);
    try std.testing.expectError(error.SignatureVerificationFailed, result);
}

test "encrypt rejects too-small output buffer" {
    var key: [key_length]u8 = undefined;
    crypto.random.bytes(&key);
    const plaintext = "data";
    var small_buf: [10]u8 = undefined; // too small for plaintext + overhead
    const result = encrypt(plaintext, &key, &small_buf);
    try std.testing.expectError(error.BufferTooSmall, result);
}

test "decrypt rejects too-short input" {
    var key: [key_length]u8 = undefined;
    crypto.random.bytes(&key);
    const short = [_]u8{ 1, 2, 3 }; // less than encryption_overhead
    var out: [10]u8 = undefined;
    const result = decrypt(&short, &key, &out);
    try std.testing.expectError(error.InputTooShort, result);
}
