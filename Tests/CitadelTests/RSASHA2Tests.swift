import Foundation
import XCTest
import Crypto
import Citadel
import NIO
@testable import NIOSSH

/// RFC 8332 (`rsa-sha2-256` / `rsa-sha2-512`) signatures for RSA keys.
final class RSASHA2Tests: XCTestCase {

    private func makeKey() throws -> Insecure.RSA.PrivateKey {
            let key = """
                -----BEGIN OPENSSH PRIVATE KEY-----
                b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
                NhAAAAAwEAAQAAAYEAw/gR2vricwFOwsiq41CAZ3agb8jeuLb6xBrSIf1yBKt0SF84Xod8
                ggYwBHN2KpbKPG61WtG0VcngxGi2JizGLSUunWSv1alMQxUCzO8OzhLEDo2aB9R/mlulug
                P68jGlpOdKL8ObocG8wtmmocYr4DL2gxa2MX3LeGVKXCuzViVBro4hfL2VkIZykPdSFBgi
                +tO/qol7uCrmSuibm/Ajmel6Q7I0gA3ItC3j3ILS39lwL8CEJVcoxaupfSXvOyzm+UzNBN
                Oi4Qvtk6w0xga2dRDhE2ANDSR1bVDTVMP/k/DJJCGP6t+ix5NGplrdNa3ue3AsU6SmbUaY
                gSgDBSpSxqRakbW3fReAgplwzZ/1hy8Uq2haT+XGjLdT9JOF5xKuQEUABAJ2ZPVrrd49Cx
                7/EuR6w1Dp27PhZIrF8AIAld8ayiZvVy+ALME4Vvp91y86VSdxC97TmBYUErhMMaQ5LaD0
                S1bB/8qTt6oEQGBPISMeyi+n9r6UAP+InEnHE32HAAAFmAbVXc8G1V3PAAAAB3NzaC1yc2
                EAAAGBAMP4Edr64nMBTsLIquNQgGd2oG/I3ri2+sQa0iH9cgSrdEhfOF6HfIIGMARzdiqW
                yjxutVrRtFXJ4MRotiYsxi0lLp1kr9WpTEMVAszvDs4SxA6NmgfUf5pbpboD+vIxpaTnSi
                /Dm6HBvMLZpqHGK+Ay9oMWtjF9y3hlSlwrs1YlQa6OIXy9lZCGcpD3UhQYIvrTv6qJe7gq
                5krom5vwI5npekOyNIANyLQt49yC0t/ZcC/AhCVXKMWrqX0l7zss5vlMzQTTouEL7ZOsNM
                YGtnUQ4RNgDQ0kdW1Q01TD/5PwySQhj+rfoseTRqZa3TWt7ntwLFOkpm1GmIEoAwUqUsak
                WpG1t30XgIKZcM2f9YcvFKtoWk/lxoy3U/SThecSrkBFAAQCdmT1a63ePQse/xLkesNQ6d
                uz4WSKxfACAJXfGsomb1cvgCzBOFb6fdcvOlUncQve05gWFBK4TDGkOS2g9EtWwf/Kk7eq
                BEBgTyEjHsovp/a+lAD/iJxJxxN9hwAAAAMBAAEAAAGBAK/bXlKPD0U66C3dm5SPehrelk
                yaClviQBhZJTbBVF8iaSBE6rXRiYa4/MARyPmhBWzDwFT2mIjft6cpfEO3rEN4+WLepvfq
                i/gq06+J21RL/Mo+gfoC1Ft1YLwTtE9BBC9+KtHADFpVHAoS/PhxeJAhy5uJdwfkpgGti9
                Q4lx94IX/+Jcjl7GCcdhTnDC3iFwnVmUr1QyPaw3x3TqTaE2ib307+jSRYukIOaEtKzud4
                HbeMYEmN9JWmXVtj/lGxESN96JCZaCf9f8QPRcjjHOIHQ5RXa8XRUDpg/ngCqv3U1c8bdy
                Ty1WFToZSt/nBz8qs89dfz9AqlQcbg7bvGxdQS5pMrzPar6Irn8rbEnN4YL569Ng5FEAui
                AmeXoqwMlIXzkNfwE4lQBMJJFGHIQFILC+ttTQiHVAp5wJ6KL1b4rF40YFZzjj9HmCPJKZ
                BP67dtd6F6DsllPqU4dbuI/4jOVg9boS985r/EhZSAqUtR3RC1KLS6bUO7AOKMfTGTKQAA
                AMBeBBbAR0qpLXlwCybGUA34xiCu5mwSvTdzD/1aMyy0n7ebBuPL0bPQ0laeQCHqflQgm6
                nX0qLpGaQIPKF0HSdukr2KKVzEuPgdEuP6Tr7sdZ87Sl8WlVi2P9zDxNpHAizFYnxXb9ft
                xaIHSu3BWNWuALt30Mn9RaX1MjV6+lanZKsniQ1cWiW1McJY39TyqL+KMzgJ/9S351wzri
                R29j1MwV0P/Azu+yoji0015UN/A7ydnPGHrHu0Pd8bu0itSiUAAADBAP3vVOu78XQdBOvo
                /dObSirz3UEbKZIaA7eYq61lbfRy+IYo+5Q5huf3mcCMeqOA4rItKu7PCIHNDbQ//h2H+X
                AH0f3Uarblm5E/Am0SiEF6/2My7G5NS+094+HsLW16l/dG3upl3DuaSTfBQc0heU1wWlEb
                CBi0fc2r5z8RLHe4xmR5MwjlfeLWATnA3ifymWmR2X+sYfnnZA6/eY4+gVlukBDOpPfAIo
                PCyEYeqqxvXqNGPzmUGxjjbB9OWgh8swAAAMEAxZAPAMpP6NYiDPNWQKRlJmxNBH5AP8nT
                JIs994TuYbhGusphd+al9wxvG0VMO/OVH+QVzQA5LWuaLt2qTMfrulnsFLZHgmueF0uq7X
                fk/frjm1ZY0dZnAXDsXR1ca4vM9BIwQBnEv7d8ausOBo/OezeakvuSigd+/M3RrdMsMJso
                CpfCnbsA570+ANELDT/OXQDfvKEKtnVhAOX5jszqvvWgD5q+9Jdutt0/Rcqtg68qUCRGvR
                vWeN+6qZf5yk3dAAAAHGphYXBASmFhcHMtTWFjQm9vay1Qcm8ubG9jYWwBAgMEBQY=
                -----END OPENSSH PRIVATE KEY-----
                """
        
        return try Insecure.RSA.PrivateKey(sshRsa: key)
    }

    /// RFC 8332 §3 splits the three identifiers: the algorithm name (`pkalg`
    /// and the signature type) is `rsa-sha2-N`, while the key blob stays typed
    /// `ssh-rsa` because the key material is unchanged.
    func testAlgorithmNames() {
        XCTAssertEqual(Insecure.RSA.SHA2PrivateKey<RSASHA2_256>.keyPrefix, "rsa-sha2-256")
        XCTAssertEqual(Insecure.RSA.SHA2PublicKey<RSASHA2_256>.userAuthAlgorithmName, "rsa-sha2-256")
        XCTAssertEqual(Insecure.RSA.SHA2Signature<RSASHA2_256>.signaturePrefix, "rsa-sha2-256")
        XCTAssertEqual(Insecure.RSA.SHA2PrivateKey<RSASHA2_512>.keyPrefix, "rsa-sha2-512")
        XCTAssertEqual(Insecure.RSA.SHA2PublicKey<RSASHA2_512>.userAuthAlgorithmName, "rsa-sha2-512")
        XCTAssertEqual(Insecure.RSA.SHA2Signature<RSASHA2_512>.signaturePrefix, "rsa-sha2-512")

        XCTAssertEqual(Insecure.RSA.SHA2PublicKey<RSASHA2_256>.publicKeyPrefix, "ssh-rsa")
        XCTAssertEqual(Insecure.RSA.SHA2PublicKey<RSASHA2_512>.publicKeyPrefix, "ssh-rsa")
        XCTAssertEqual(Insecure.RSA.PublicKey.publicKeyPrefix, "ssh-rsa")
        XCTAssertEqual(Insecure.RSA.PublicKey.userAuthAlgorithmName, "ssh-rsa")
    }

    func testSHA256SignatureRoundTrips() throws {
        let key = Insecure.RSA.SHA2PrivateKey<RSASHA2_256>(try makeKey())
        let message = Array("the quick brown fox".utf8)
        let signature = try key.signature(for: message)
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: message))
    }

    func testSHA512SignatureRoundTrips() throws {
        let key = Insecure.RSA.SHA2PrivateKey<RSASHA2_512>(try makeKey())
        let message = Array("the quick brown fox".utf8)
        let signature = try key.signature(for: message)
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: message))
    }

    func testSignatureRejectsTamperedMessage() throws {
        let key = Insecure.RSA.SHA2PrivateKey<RSASHA2_256>(try makeKey())
        let signature = try key.signature(for: Array("the quick brown fox".utf8))
        XCTAssertFalse(key.publicKey.isValidSignature(signature, for: Array("the quick brown cat".utf8)))
    }

    /// A SHA-256 signature must not verify under the SHA-512 variant, and the
    /// wrong concrete signature type must be refused outright.
    func testVariantsDoNotCrossVerify() throws {
        let base = try makeKey()
        let sha256Key = Insecure.RSA.SHA2PrivateKey<RSASHA2_256>(base)
        let sha512Key = Insecure.RSA.SHA2PrivateKey<RSASHA2_512>(base)
        let message = Array("the quick brown fox".utf8)
        let signature = try sha256Key.signature(for: message)
        XCTAssertFalse(sha512Key.publicKey.isValidSignature(signature, for: message))
    }

    /// The wire body is plain `ssh-rsa` (mpint e, mpint n) - only the algorithm
    /// name around it changes, which is what RFC 8332 requires.
    func testPublicKeyBodyMatchesSSHRSA() throws {
        let base = try makeKey()
        let sha2 = Insecure.RSA.SHA2PrivateKey<RSASHA2_256>(base).publicKey

        var legacyBuffer = ByteBuffer()
        _ = base.publicKey.write(to: &legacyBuffer)
        var sha2Buffer = ByteBuffer()
        _ = sha2.write(to: &sha2Buffer)

        XCTAssertEqual(legacyBuffer, sha2Buffer)
    }

    // MARK: - Offer list

    /// What one offered public key puts on the wire: the algorithm name NIOSSH
    /// writes as `pkalg`, and the type string the key blob itself carries.
    private struct OfferedKey: Equatable {
        var algorithmName: String
        var blobType: String
    }

    /// Drives the delegate until it runs out of offers, and returns both
    /// identifiers for each offered public key.
    ///
    /// The offer list is private to `SSHAuthenticationMethod`, so the only way
    /// to observe it is the way NIOSSH does: ask for the next offer until the
    /// delegate refuses.
    ///
    /// The two identifiers are read from the two members NIOSSH itself reads:
    /// `NIOSSHPublicKey.userAuthAlgorithmName`, which `writeUserAuthRequestMessage`
    /// writes as `pkalg`, and the leading SSH string of `write(to:)`, which is
    /// the blob's own type. Since RFC 8332 typing landed, the blob string is
    /// `ssh-rsa` for every RSA offer and no longer distinguishes the variants -
    /// so the variant has to be read from the algorithm name.
    private func offeredPublicKeys(
        _ method: SSHAuthenticationMethod,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> [OfferedKey] {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let loop = group.next()

        var offered: [OfferedKey] = []
        // The list is finite and short; the cap only stops a runaway loop from
        // hanging the suite if the delegate ever stops draining itself.
        for _ in 0 ..< 16 {
            let promise = loop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
            method.nextAuthenticationType(
                availableMethods: .publicKey,
                nextChallengePromise: promise
            )

            let offer: NIOSSHUserAuthenticationOffer?
            do {
                offer = try promise.futureResult.wait()
            } catch {
                // The delegate is out of offers.
                return offered
            }
            guard case .privateKey(let privateKey) = offer?.offer else {
                XCTFail("expected a private key offer, got \(String(describing: offer?.offer))", file: file, line: line)
                return offered
            }

            let publicKey = privateKey.publicKey
            var buffer = ByteBuffer()
            publicKey.write(to: &buffer)
            guard
                let length = buffer.readInteger(as: UInt32.self),
                let blobType = buffer.readString(length: Int(length))
            else {
                XCTFail("offered public key does not begin with an SSH string", file: file, line: line)
                return offered
            }
            offered.append(
                OfferedKey(
                    algorithmName: String(publicKey.userAuthAlgorithmName),
                    blobType: blobType
                )
            )
        }

        XCTFail("delegate never ran out of offers", file: file, line: line)
        return offered
    }

    /// The default offer list is SHA-2 only.
    ///
    /// NIOSSH signs an offer as it makes it - `UserAuthenticationMethod.swift`,
    /// `let signature = try privateKeyRequest.privateKey.sign(dataToSign)` -
    /// with no two-phase probe, so an `ssh-rsa` offer is a real SHA-1 signature
    /// on the wire rather than an advertisement that costs nothing.
    ///
    /// The equality is the positive half of this check: it fails loudly if the
    /// SHA-2 offers ever stop being made, which is what would otherwise let the
    /// `ssh-rsa` half below pass by matching nothing at all.
    ///
    /// The negative reads the ALGORITHM name, not the blob type. Since RFC 8332
    /// typing, every RSA blob here says `ssh-rsa`, so a negative against the
    /// blob type could never match and would pass whatever was offered. The
    /// SHA-1 type's algorithm name is `ssh-rsa` — `Insecure.RSA.PublicKey`
    /// declares no separate `userAuthAlgorithmName`, so the protocol default
    /// hands back its blob prefix — and that is the string a SHA-1 offer would
    /// put in `pkalg`.
    func testDefaultOfferListIsSHA2Only() throws {
        let offered = try offeredPublicKeys(
            .rsaSHA2(username: "test", privateKey: makeKey())
        )

        XCTAssertEqual(offered.map(\.algorithmName), [
            Insecure.RSA.SHA2PublicKey<RSASHA2_512>.userAuthAlgorithmName,
            Insecure.RSA.SHA2PublicKey<RSASHA2_256>.userAuthAlgorithmName,
        ])
        XCTAssertFalse(
            offered.map(\.algorithmName).contains(Insecure.RSA.PublicKey.userAuthAlgorithmName)
        )
    }

    /// Every offered RSA blob is typed `ssh-rsa`, whichever algorithm carries
    /// it. This is the offer-list half of `RSAUserAuthBlobTypingTests`, and the
    /// reason the two tests above can no longer tell the variants apart by the
    /// blob string.
    func testEveryOfferedRSABlobIsTypedSSHRSA() throws {
        let offered = try offeredPublicKeys(
            .rsaSHA2(username: "test", privateKey: makeKey(), includeSHA1Fallback: true)
        )

        XCTAssertEqual(offered.count, 3)
        XCTAssertEqual(
            Set(offered.map(\.blobType)),
            [Insecure.RSA.PublicKey.publicKeyPrefix]
        )
    }

    /// The legacy offer still exists - it just has to be asked for.
    func testSHA1FallbackIsOfferedWhenAskedFor() throws {
        let offered = try offeredPublicKeys(
            .rsaSHA2(username: "test", privateKey: makeKey(), includeSHA1Fallback: true)
        )

        XCTAssertEqual(offered.map(\.algorithmName), [
            Insecure.RSA.SHA2PublicKey<RSASHA2_512>.userAuthAlgorithmName,
            Insecure.RSA.SHA2PublicKey<RSASHA2_256>.userAuthAlgorithmName,
            Insecure.RSA.PublicKey.userAuthAlgorithmName,
        ])
    }
}
