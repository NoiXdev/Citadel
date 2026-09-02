import CCryptoBoringSSL
import BigInt
import Foundation
import Crypto
import NIO
import NIOSSH

public struct InvalidOpenSSHKey: Error {
    public enum UnsupportedFeature: String {
        case multipleKeys, unsupportedPublicKeyType, unsupportedKDF, unsupportedCipher
    }

    let reason: String

    static let invalidUTF8String = InvalidOpenSSHKey(reason: "invalidUTF8String")
    static let missingPublicKeyBuffer = InvalidOpenSSHKey(reason: "missingPublicKeyBuffer")
    static let missingPrivateKeyBuffer = InvalidOpenSSHKey(reason: "missingPrivateKeyBuffer")
    static let missingPublicKeyInPrivateKey = InvalidOpenSSHKey(reason: "missingPublicKeyInPrivateKey")
    static let missingComment = InvalidOpenSSHKey(reason: "missingComment")
    static let invalidCheck = InvalidOpenSSHKey(reason: "invalidCheck")
    static let invalidPublicKeyInPrivateKey = InvalidOpenSSHKey(reason: "invalidPublicKeyInPrivateKey")
    static let invalidLayout = InvalidOpenSSHKey(reason: "invalidLayout")
    static let invalidPadding = InvalidOpenSSHKey(reason: "invalidPadding")
    static let invalidOpenSSHBoundary = InvalidOpenSSHKey(reason: "invalidOpenSSHBoundary")
    static let invalidBase64Payload = InvalidOpenSSHKey(reason: "invalidBase64Payload")
    static let invalidOpenSSHPrefix = InvalidOpenSSHKey(reason: "invalidOpenSSHPrefix")
    static func unsupportedFeature(_ feature: UnsupportedFeature) -> InvalidOpenSSHKey {
        InvalidOpenSSHKey(reason: "UnsupportedFeature: \(feature.rawValue)")
    }
    static let invalidPublicKeyPrefix = InvalidOpenSSHKey(reason: "invalidPublicKeyPrefix")
    static let invalidOrUnsupportedBCryptConfig = InvalidOpenSSHKey(reason: "invalidOrUnsupportedBCryptConfig")
    static let unexpectedKDFNoneOptions = InvalidOpenSSHKey(reason: "unexpectedKDFNoneOptions")
    static let invalidCurveName = InvalidOpenSSHKey(reason: "invalidCurveName")
    static let invalidECDSAPoint = InvalidOpenSSHKey(reason: "invalidECDSAPoint")
    static let invalidECDSAScalar = InvalidOpenSSHKey(reason: "invalidECDSAScalar")
}

/// Thrown when an OpenSSH private key container holds a key of a different type
/// than the initialiser that was asked to read it — most usefully, one ECDSA
/// curve's initialiser applied to another curve's file.
///
/// This is separate from `InvalidOpenSSHKey`, and carries both type names,
/// because it is the one parse failure a caller can act on: it says which
/// initialiser the file wanted.
public struct OpenSSHKeyTypeMismatch: Error, Equatable, CustomStringConvertible {
    /// The key type the initialiser reads, e.g. `ecdsa-sha2-nistp256`.
    public let expected: String

    /// The key type the container holds.
    public let found: String

    public init(expected: String, found: String) {
        self.expected = expected
        self.found = found
    }

    public var description: String {
        "OpenSSH key type mismatch: expected \(expected), found \(found)"
    }
}

public typealias InvalidKey = InvalidOpenSSHKey

extension Curve25519.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Curve25519.Signing.PublicKey {
        guard var publicKeyBuffer = buffer.readSSHBuffer() else {
            throw InvalidOpenSSHKey.missingPublicKeyBuffer
        }
        
        return try self.init(rawRepresentation: publicKeyBuffer.readBytes(length: publicKeyBuffer.readableBytes)!)
    }
    
    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeData(self.rawRepresentation)
    }
}

extension Curve25519.Signing.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = Curve25519.Signing.PublicKey
    static var publicKeyPrefix: String { "ssh-ed25519" }
    static var privateKeyPrefix: String { "ssh-ed25519" }
    static var keyType: OpenSSH.KeyType { .sshED25519 }
    
    /// Creates a new Curve25519 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshEd25519 data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshEd25519: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }
    }
    
    /// Creates a new Curve25519 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshEd25519 key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<Curve25519.Signing.PrivateKey>.init(string: key, decryptionKey: decryptionKey).privateKey
    }
}

extension Insecure.RSA.PublicKey: ByteBufferConvertible {
    func write(to buffer: inout ByteBuffer) {
        let _: Int = self.write(to: &buffer)
    }
}

extension Insecure.RSA.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = Insecure.RSA.PublicKey
    
    static var publicKeyPrefix: String { "ssh-rsa" }
    static var privateKeyPrefix: String { "ssh-rsa" }
    static var keyType: OpenSSH.KeyType { .sshRSA }
    
    /// Creates a new Curve25519 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public convenience init(sshRsa data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshRsa: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }
    }
    
    /// Creates a new Curve25519 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public convenience init(sshRsa key: String, decryptionKey: Data? = nil) throws {
        let privateKey = try OpenSSH.PrivateKey<Insecure.RSA.PrivateKey>.init(string: key, decryptionKey: decryptionKey).privateKey
        let publicKey = privateKey.publicKey as! Insecure.RSA.PublicKey
        
        // Copy, so that our values stored in `privateKey` aren't freed when exciting the initializers scope
        let modulus = CCryptoBoringSSL_BN_new()!
        let publicExponent = CCryptoBoringSSL_BN_new()!
        let privateExponent = CCryptoBoringSSL_BN_new()!
        
        CCryptoBoringSSL_BN_copy(modulus, publicKey.modulus)
        CCryptoBoringSSL_BN_copy(publicExponent, publicKey.publicExponent)
        CCryptoBoringSSL_BN_copy(privateExponent, privateKey.privateExponent)
        
        self.init(privateExponent: privateExponent, publicExponent: publicExponent, modulus: modulus)
    }
}

extension P256.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> P256.Signing.PublicKey {
        try self.init(x963Representation: OpenSSH.ECDSACurve.nistp256.readPoint(consuming: &buffer))
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        OpenSSH.ECDSACurve.nistp256.writePoint(x963Representation, to: &buffer)
    }
}

extension P384.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> P384.Signing.PublicKey {
        try self.init(x963Representation: OpenSSH.ECDSACurve.nistp384.readPoint(consuming: &buffer))
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        OpenSSH.ECDSACurve.nistp384.writePoint(x963Representation, to: &buffer)
    }
}

extension P521.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> P521.Signing.PublicKey {
        try self.init(x963Representation: OpenSSH.ECDSACurve.nistp521.readPoint(consuming: &buffer))
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        OpenSSH.ECDSACurve.nistp521.writePoint(x963Representation, to: &buffer)
    }
}

extension P256.Signing.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = P256.Signing.PublicKey

    static var publicKeyPrefix: String { OpenSSH.KeyType.ecdsaP256.rawValue }
    static var privateKeyPrefix: String { OpenSSH.KeyType.ecdsaP256.rawValue }
    static var keyType: OpenSSH.KeyType { .ecdsaP256 }

    static func keyTypeMismatch(found: String) -> any Error {
        OpenSSHKeyTypeMismatch(expected: publicKeyPrefix, found: found)
    }

    /// Creates a new P-256 private key from an OpenSSH private key file.
    /// - Parameters:
    ///  - data: The contents of the OpenSSH private key file, as UTF-8.
    ///  - decryptionKey: The passphrase to decrypt the private key with, if it
    ///    is passphrase-protected.
    public init(sshEcdsa data: Data, decryptionKey: Data? = nil) throws {
        guard let string = String(data: data, encoding: .utf8) else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }

        try self.init(sshEcdsa: string, decryptionKey: decryptionKey)
    }

    /// Creates a new P-256 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    ///  - decryptionKey: The passphrase to decrypt the private key with, if it
    ///    is passphrase-protected.
    public init(sshEcdsa key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<P256.Signing.PrivateKey>(
            string: key,
            decryptionKey: decryptionKey
        ).privateKey
    }
}

extension P384.Signing.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = P384.Signing.PublicKey

    static var publicKeyPrefix: String { OpenSSH.KeyType.ecdsaP384.rawValue }
    static var privateKeyPrefix: String { OpenSSH.KeyType.ecdsaP384.rawValue }
    static var keyType: OpenSSH.KeyType { .ecdsaP384 }

    static func keyTypeMismatch(found: String) -> any Error {
        OpenSSHKeyTypeMismatch(expected: publicKeyPrefix, found: found)
    }

    /// Creates a new P-384 private key from an OpenSSH private key file.
    /// - Parameters:
    ///  - data: The contents of the OpenSSH private key file, as UTF-8.
    ///  - decryptionKey: The passphrase to decrypt the private key with, if it
    ///    is passphrase-protected.
    public init(sshEcdsa data: Data, decryptionKey: Data? = nil) throws {
        guard let string = String(data: data, encoding: .utf8) else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }

        try self.init(sshEcdsa: string, decryptionKey: decryptionKey)
    }

    /// Creates a new P-384 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    ///  - decryptionKey: The passphrase to decrypt the private key with, if it
    ///    is passphrase-protected.
    public init(sshEcdsa key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<P384.Signing.PrivateKey>(
            string: key,
            decryptionKey: decryptionKey
        ).privateKey
    }
}

extension P521.Signing.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = P521.Signing.PublicKey

    static var publicKeyPrefix: String { OpenSSH.KeyType.ecdsaP521.rawValue }
    static var privateKeyPrefix: String { OpenSSH.KeyType.ecdsaP521.rawValue }
    static var keyType: OpenSSH.KeyType { .ecdsaP521 }

    static func keyTypeMismatch(found: String) -> any Error {
        OpenSSHKeyTypeMismatch(expected: publicKeyPrefix, found: found)
    }

    /// Creates a new P-521 private key from an OpenSSH private key file.
    /// - Parameters:
    ///  - data: The contents of the OpenSSH private key file, as UTF-8.
    ///  - decryptionKey: The passphrase to decrypt the private key with, if it
    ///    is passphrase-protected.
    public init(sshEcdsa data: Data, decryptionKey: Data? = nil) throws {
        guard let string = String(data: data, encoding: .utf8) else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }

        try self.init(sshEcdsa: string, decryptionKey: decryptionKey)
    }

    /// Creates a new P-521 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    ///  - decryptionKey: The passphrase to decrypt the private key with, if it
    ///    is passphrase-protected.
    public init(sshEcdsa key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<P521.Signing.PrivateKey>(
            string: key,
            decryptionKey: decryptionKey
        ).privateKey
    }
}
