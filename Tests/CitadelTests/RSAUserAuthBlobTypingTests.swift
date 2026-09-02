import Foundation
import XCTest
import Crypto
import Citadel
import NIO
@testable import NIOSSH

/// RFC 8332 §3 names three separate identifiers in a `publickey` user-auth
/// request for an RSA key:
///
/// * `pkalg` — the public key ALGORITHM name: `rsa-sha2-512` / `rsa-sha2-256`
/// * the key BLOB, whose inner type string stays `ssh-rsa` (the key material
///   is the same `e`, `n` pair; only the algorithm around it changes)
/// * the SIGNATURE, typed with the algorithm name again: `rsa-sha2-512`
///
/// OpenSSH tolerates a blob typed with the algorithm name; Go's
/// `x/crypto/ssh` refuses it, which is what these tests exist to pin.
final class RSAUserAuthBlobTypingTests: XCTestCase {

    private func makeKey() throws -> Insecure.RSA.PrivateKey {
        let key = """
            -----BEGIN OPENSSH PRIVATE KEY-----
            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
            -----END OPENSSH PRIVATE KEY-----
            """
        return try Insecure.RSA.PrivateKey(sshRsa: key)
    }

    // MARK: - (a) The key blob is typed `ssh-rsa`

    /// Reads the leading SSH string of a serialized public key blob.
    private func blobType(
        of key: NIOSSHPublicKey,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> String? {
        var buffer = ByteBuffer()
        key.write(to: &buffer)
        guard let type = buffer.readSSHStringAsString() else {
            XCTFail("blob does not begin with an SSH string", file: file, line: line)
            return nil
        }
        return type
    }

    func testSHA512KeyBlobIsTypedSSHRSA() throws {
        let key = NIOSSHPrivateKey(custom: Insecure.RSA.SHA2PrivateKey<RSASHA2_512>(try makeKey()))
        XCTAssertEqual(blobType(of: key.publicKey), "ssh-rsa")
    }

    func testSHA256KeyBlobIsTypedSSHRSA() throws {
        let key = NIOSSHPrivateKey(custom: Insecure.RSA.SHA2PrivateKey<RSASHA2_256>(try makeKey()))
        XCTAssertEqual(blobType(of: key.publicKey), "ssh-rsa")
    }

    // MARK: - (b) The algorithm name stays on the private key and the signature

    func testAlgorithmNamesAreNotTheBlobType() {
        XCTAssertEqual(Insecure.RSA.SHA2PrivateKey<RSASHA2_512>.keyPrefix, "rsa-sha2-512")
        XCTAssertEqual(Insecure.RSA.SHA2Signature<RSASHA2_512>.signaturePrefix, "rsa-sha2-512")
        XCTAssertEqual(Insecure.RSA.SHA2PrivateKey<RSASHA2_256>.keyPrefix, "rsa-sha2-256")
        XCTAssertEqual(Insecure.RSA.SHA2Signature<RSASHA2_256>.signaturePrefix, "rsa-sha2-256")
    }

    // MARK: - (c) The whole request, as NIOSSH writes it

    /// The three identifiers, read back out of the bytes NIOSSH writes for a
    /// signed `publickey` request.
    private struct RequestIdentifiers: Equatable {
        var pkalg: String
        var blobType: String
        var signatureType: String
    }

    private func requestIdentifiers<Variant: RSASHA2Variant>(
        _ variant: Variant.Type
    ) throws -> RequestIdentifiers {
        let privateKey = NIOSSHPrivateKey(custom: Insecure.RSA.SHA2PrivateKey<Variant>(try makeKey()))
        let publicKey = privateKey.publicKey
        let signature = try privateKey.sign(digest: SHA256.hash(data: Array("payload".utf8)))

        let message = SSHMessage.UserAuthRequestMessage(
            username: "test",
            service: "ssh-connection",
            method: .publicKey(.known(key: publicKey, signature: signature))
        )

        var buffer = ByteBuffer()
        buffer.writeUserAuthRequestMessage(message)

        guard
            let _ = buffer.readSSHStringAsString(),      // username
            let _ = buffer.readSSHStringAsString(),      // service
            let method = buffer.readSSHStringAsString(), // "publickey"
            let signed = buffer.readSSHBoolean(),
            let pkalg = buffer.readSSHStringAsString(),
            var blob = buffer.readSSHString(),
            let blobType = blob.readSSHStringAsString(),
            var signatureBlob = buffer.readSSHString(),
            let signatureType = signatureBlob.readSSHStringAsString()
        else {
            throw XCTSkip("could not parse the request NIOSSH wrote")
        }
        XCTAssertEqual(method, "publickey")
        XCTAssertTrue(signed)

        return RequestIdentifiers(pkalg: pkalg, blobType: blobType, signatureType: signatureType)
    }

    /// RFC 8332 §3: `pkalg` is the algorithm, the blob is `ssh-rsa`, the
    /// signature is the algorithm again.
    func testSHA512UserAuthRequestUsesRFC8332Identifiers() throws {
        XCTAssertEqual(
            try requestIdentifiers(RSASHA2_512.self),
            RequestIdentifiers(
                pkalg: "rsa-sha2-512",
                blobType: "ssh-rsa",
                signatureType: "rsa-sha2-512"
            )
        )
    }

    func testSHA256UserAuthRequestUsesRFC8332Identifiers() throws {
        XCTAssertEqual(
            try requestIdentifiers(RSASHA2_256.self),
            RequestIdentifiers(
                pkalg: "rsa-sha2-256",
                blobType: "ssh-rsa",
                signatureType: "rsa-sha2-256"
            )
        )
    }
}
