#pragma once

#include <cstdint>
#include <span>
#include <vector>

#ifdef RAVEN_OPENSSL
#include <openssl/x509.h>
#endif

namespace raven {

// What WinVerifyTrust finds in a signed file: its status as the Windows trust error (zero when the file is trusted), and the certificates
// from the signer up to the root, DER encoded, as far as the chain could be built.
struct AuthenticodeResult {
	uint32_t status = 0;
	std::vector<std::vector<uint8_t>> chain;
	bool anchored = false;
};

// Checks the Authenticode signature of a program or library, a cabinet or an installer database: the digest of the content, the
// signer's signature over it, and the chain of the signer's certificate to a trusted root at the time the signature was stamped.
AuthenticodeResult verify_authenticode(std::span<const uint8_t> file);
// The PKCS #7 signature a program, cabinet or installer database carries; empty when it carries none.
std::vector<uint8_t> embedded_signature(std::span<const uint8_t> file);
// The digest a security catalog lists a file under: a program or library hashed as for its signature, any other file whole. Empty
// without the cryptography library.
std::vector<uint8_t> subject_digest(std::span<const uint8_t> file, bool sha256);

#ifdef RAVEN_OPENSSL
// The trust anchors: the host's certificate bundle and the code signing roots beside the runtime, which every Windows installation
// carries in its root store.
X509_STORE *trust_anchors();
#endif

}
