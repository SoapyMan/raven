// The Cryptography API: Next Generation primitives of bcrypt.dll: hashes and HMAC, symmetric ciphers, key agreement, signatures and key
// derivation, worked with OpenSSL. A handle a program holds is a small block of its own memory standing for a host object, since programs
// check that the handles they are given point at memory; the object buffers programs allocate for hashes and keys stay unused.
#include "kernel_context.h"
#include "text.h"

#ifdef RAVEN_OPENSSL
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <variant>

namespace raven {

#ifdef RAVEN_OPENSSL

namespace {

constexpr uint32_t status_success = 0, status_invalid_handle = 0xc0000008, status_invalid_parameter = 0xc000000d, status_no_memory = 0xc0000017,
	status_buffer_too_small = 0xc0000023, status_not_supported = 0xc00000bb, status_invalid_buffer_size = 0xc0000206,
	status_not_found = 0xc0000225, status_invalid_signature = 0xc000a000, status_auth_tag_mismatch = 0xc000a002,
	status_unsuccessful = 0xc0000001, status_data_error = 0xc000003e;
constexpr uint32_t hmac_flag = 0x8, block_padding = 0x1, pad_none = 0x1, pad_pkcs1 = 0x2, pad_oaep = 0x4, pad_pss = 0x8;
constexpr uint32_t magic_rsa_public = 0x31415352, magic_rsa_private = 0x32415352, magic_rsa_full = 0x33415352, magic_dh_public = 0x42504844,
	magic_dh_private = 0x56504844, magic_dh_parameters = 0x4d504844, magic_ecdh_public_generic = 0x504b4345,
	magic_ecdh_private_generic = 0x564b4345, magic_ecdsa_public_generic = 0x50444345, magic_ecdsa_private_generic = 0x56444345;

enum class Kind { hash, cipher, ecdh, ecdsa, rsa, dh, rng };

struct Algorithm {
	std::u16string name;
	Kind kind = Kind::hash;
	bool hmac = false;
	bool gmac = false; // AES-GMAC: a MAC keyed by the hash secret, its nonce set as the hash's IV property
	std::string digest; // the OpenSSL name of a hash
	std::u16string chaining = u"ChainingModeCBC";
	std::string curve; // the OpenSSL group of an elliptic-curve algorithm, once known
	std::vector<uint8_t> dh_parameters; // p and g, big-endian, of the same length
	uint32_t message_block = 0;
};

struct Hash {
	std::shared_ptr<Algorithm> algorithm;
	std::vector<uint8_t> secret, nonce;
	EVP_MD_CTX *digest = nullptr;
	EVP_MAC_CTX *mac = nullptr;
	~Hash()
	{
		EVP_MD_CTX_free(digest);
		EVP_MAC_CTX_free(mac);
	}
};

struct Key {
	std::shared_ptr<Algorithm> algorithm;
	// A symmetric key: its bytes, mode and the feedback a call without an IV continues from.
	std::vector<uint8_t> secret, feedback;
	std::u16string chaining;
	uint32_t message_block = 0;
	// An asymmetric key, and what generating one waits for.
	EVP_PKEY *pair = nullptr;
	uint32_t bits = 0;
	std::string curve;
	std::vector<uint8_t> dh_parameters;
	~Key() { EVP_PKEY_free(pair); }
};

struct Secret {
	std::vector<uint8_t> value; // big-endian, as the agreement computes it
};

using Object = std::variant<std::shared_ptr<Algorithm>, std::shared_ptr<Hash>, std::shared_ptr<Key>, std::shared_ptr<Secret>>;

// The objects behind the handles. A handle is the address of a small block of the process's memory, as CNG's handles point to its
// structures there: programs check that one is readable memory before they trust it.
class Table {
public:
	std::function<uint64_t()> allocate;
	std::function<void(uint64_t)> release;
	// The guest allocator can give the processor to another guest thread, which may come here on the same host thread: it is never
	// called, nor an object destroyed, with the lock held.
	uint64_t add(Object object)
	{
		const uint64_t handle = allocate ? allocate() : 0;
		if (!handle)
			return 0;
		std::lock_guard guard(lock);
		objects.emplace(handle, std::move(object));
		return handle;
	}
	template<typename T> std::shared_ptr<T> get(uint64_t handle)
	{
		std::lock_guard guard(lock);
		const auto found = objects.find(handle);
		if (found == objects.end())
			return nullptr;
		const auto *value = std::get_if<std::shared_ptr<T>>(&found->second);
		return value ? *value : nullptr;
	}
	bool remove(uint64_t handle)
	{
		Object removed;
		{
			std::lock_guard guard(lock);
			const auto found = objects.find(handle);
			if (found == objects.end())
				return false;
			removed = std::move(found->second);
			objects.erase(found);
		}
		if (release)
			release(handle);
		return true;
	}

private:
	std::mutex lock;
	std::map<uint64_t, Object> objects;
};

Table &table()
{
	static Table instance;
	return instance;
}

bool tracing()
{
	static const bool enabled = std::getenv("RAVEN_TRACE_BCRYPT") != nullptr;
	return enabled;
}

std::string curve_group(std::u16string_view name)
{
	if (name == u"nistP256" || name == u"secP256r1")
		return "prime256v1";
	if (name == u"nistP384" || name == u"secP384r1")
		return "secp384r1";
	if (name == u"nistP521" || name == u"secP521r1")
		return "secp521r1";
	if (name == u"secP256k1")
		return "secp256k1";
	if (name == u"curve25519")
		return "X25519";
	return {};
}

std::u16string curve_name(const std::string &group)
{
	if (group == "prime256v1")
		return u"nistP256";
	if (group == "secp384r1")
		return u"nistP384";
	if (group == "secp521r1")
		return u"nistP521";
	if (group == "secp256k1")
		return u"secP256k1";
	if (group == "X25519")
		return u"curve25519";
	return {};
}

size_t field_bytes(const std::string &group)
{
	if (group == "prime256v1" || group == "secp256k1" || group == "X25519")
		return 32;
	if (group == "secp384r1")
		return 48;
	if (group == "secp521r1")
		return 66;
	return 0;
}

// The algorithm an identifier names, with the hash name and family it stands for.
std::shared_ptr<Algorithm> make_algorithm(std::u16string_view name, uint32_t flags)
{
	auto algorithm = std::make_shared<Algorithm>();
	algorithm->name = name;
	algorithm->hmac = (flags & hmac_flag) != 0;
	static const std::map<std::u16string_view, const char *> hashes{{u"MD5", "MD5"}, {u"SHA1", "SHA1"}, {u"SHA256", "SHA256"},
		{u"SHA384", "SHA384"}, {u"SHA512", "SHA512"}, {u"SHA3-256", "SHA3-256"}, {u"SHA3-384", "SHA3-384"}, {u"SHA3-512", "SHA3-512"}};
	if (const auto found = hashes.find(name); found != hashes.end()) {
		algorithm->kind = Kind::hash;
		algorithm->digest = found->second;
	} else if (name == u"AES-GMAC") {
		algorithm->kind = Kind::hash;
		algorithm->gmac = true;
	} else if (name == u"AES" || name == u"3DES" || name == u"DES") {
		algorithm->kind = Kind::cipher;
	} else if (name == u"ECDH_P256" || name == u"ECDH_P384" || name == u"ECDH_P521" || name == u"ECDH") {
		algorithm->kind = Kind::ecdh;
		if (name != u"ECDH")
			algorithm->curve = curve_group(name == u"ECDH_P256" ? u"nistP256" : name == u"ECDH_P384" ? u"nistP384" : u"nistP521");
	} else if (name == u"ECDSA_P256" || name == u"ECDSA_P384" || name == u"ECDSA_P521" || name == u"ECDSA") {
		algorithm->kind = Kind::ecdsa;
		if (name != u"ECDSA")
			algorithm->curve = curve_group(name == u"ECDSA_P256" ? u"nistP256" : name == u"ECDSA_P384" ? u"nistP384" : u"nistP521");
	} else if (name == u"RSA" || name == u"RSA_SIGN") {
		algorithm->kind = Kind::rsa;
	} else if (name == u"DH") {
		algorithm->kind = Kind::dh;
	} else if (name == u"RNG" || name == u"FIPS186DSARNG") {
		algorithm->kind = Kind::rng;
	} else {
		return nullptr;
	}
	return algorithm;
}

// The handles Windows 10 answers for without opening a provider.
std::shared_ptr<Algorithm> pseudo_algorithm(uint64_t handle)
{
	static const std::map<uint64_t, std::pair<std::u16string_view, uint32_t>> pseudo{{0x21, {u"MD5", 0}}, {0x31, {u"SHA1", 0}},
		{0x41, {u"SHA256", 0}}, {0x51, {u"SHA384", 0}}, {0x61, {u"SHA512", 0}}, {0x81, {u"RNG", 0}}, {0x91, {u"MD5", hmac_flag}},
		{0xa1, {u"SHA1", hmac_flag}}, {0xb1, {u"SHA256", hmac_flag}}, {0xc1, {u"SHA384", hmac_flag}}, {0xd1, {u"SHA512", hmac_flag}},
		{0xe1, {u"RSA", 0}}, {0xf1, {u"ECDSA", 0}}};
	static std::mutex lock;
	static std::map<uint64_t, std::shared_ptr<Algorithm>> made;
	const auto found = pseudo.find(handle);
	if (found == pseudo.end())
		return nullptr;
	std::lock_guard guard(lock);
	auto &algorithm = made[handle];
	if (!algorithm)
		algorithm = make_algorithm(found->second.first, found->second.second);
	return algorithm;
}

std::shared_ptr<Algorithm> algorithm_of(uint64_t handle)
{
	if (auto algorithm = pseudo_algorithm(handle))
		return algorithm;
	return table().get<Algorithm>(handle);
}

size_t digest_size(const Algorithm &algorithm)
{
	if (algorithm.gmac)
		return 16;
	const EVP_MD *md = EVP_get_digestbyname(algorithm.digest.c_str());
	return md ? size_t(EVP_MD_get_size(md)) : 0;
}

size_t digest_block(const Algorithm &algorithm)
{
	if (algorithm.gmac)
		return 16;
	const EVP_MD *md = EVP_get_digestbyname(algorithm.digest.c_str());
	return md ? size_t(EVP_MD_get_block_size(md)) : 0;
}

size_t cipher_block(const Algorithm &algorithm)
{
	return algorithm.name == u"AES" ? 16 : 8;
}

bool start_hash(Hash &hash)
{
	if (hash.algorithm->gmac) {
		const size_t size = hash.secret.size();
		if (size != 16 && size != 24 && size != 32)
			return false;
		EVP_MAC *mac = EVP_MAC_fetch(nullptr, "GMAC", nullptr);
		if (!mac)
			return false;
		EVP_MAC_CTX_free(hash.mac);
		hash.mac = EVP_MAC_CTX_new(mac);
		EVP_MAC_free(mac);
		char cipher[16];
		std::snprintf(cipher, sizeof(cipher), "AES-%zu-GCM", size * 8);
		// Until the program sets a nonce the MAC starts from twelve zero bytes, so that creating the hash succeeds as on Windows.
		static const uint8_t zero_nonce[12] = {};
		auto &nonce = hash.nonce;
		OSSL_PARAM parameters[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher, 0),
			OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV, nonce.empty() ? const_cast<uint8_t *>(zero_nonce) : nonce.data(),
				nonce.empty() ? sizeof(zero_nonce) : nonce.size()),
			OSSL_PARAM_construct_end()};
		return hash.mac && EVP_MAC_init(hash.mac, hash.secret.data(), size, parameters) == 1;
	}
	if (hash.algorithm->hmac) {
		EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
		if (!mac)
			return false;
		EVP_MAC_CTX_free(hash.mac);
		hash.mac = EVP_MAC_CTX_new(mac);
		EVP_MAC_free(mac);
		OSSL_PARAM parameters[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, hash.algorithm->digest.data(), 0), OSSL_PARAM_construct_end()};
		static const uint8_t none = 0;
		return hash.mac && EVP_MAC_init(hash.mac, hash.secret.empty() ? &none : hash.secret.data(), hash.secret.size(), parameters) == 1;
	}
	if (!hash.digest)
		hash.digest = EVP_MD_CTX_new();
	return hash.digest && EVP_DigestInit_ex(hash.digest, EVP_get_digestbyname(hash.algorithm->digest.c_str()), nullptr) == 1;
}

bool update_hash(Hash &hash, const std::vector<uint8_t> &data)
{
	if (hash.mac)
		return EVP_MAC_update(hash.mac, data.data(), data.size()) == 1;
	return EVP_DigestUpdate(hash.digest, data.data(), data.size()) == 1;
}

std::vector<uint8_t> finish_hash(Hash &hash)
{
	std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
	size_t length = 0;
	unsigned int digest_length = 0;
	if (hash.mac) {
		if (EVP_MAC_final(hash.mac, out.data(), &length, out.size()) != 1)
			return {};
	} else {
		if (EVP_DigestFinal_ex(hash.digest, out.data(), &digest_length) != 1)
			return {};
		length = digest_length;
	}
	out.resize(length);
	return out;
}

std::vector<uint8_t> digest(const std::string &name, const std::vector<uint8_t> &data)
{
	std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
	unsigned int length = 0;
	const EVP_MD *md = EVP_get_digestbyname(name.c_str());
	if (!md || EVP_Digest(data.data(), data.size(), out.data(), &length, md, nullptr) != 1)
		return {};
	out.resize(length);
	return out;
}

std::string digest_name(std::u16string_view algorithm)
{
	if (algorithm == u"SHA1")
		return "SHA1";
	if (algorithm == u"SHA256")
		return "SHA256";
	if (algorithm == u"SHA384")
		return "SHA384";
	if (algorithm == u"SHA512")
		return "SHA512";
	if (algorithm == u"MD5")
		return "MD5";
	return {};
}

std::vector<uint8_t> big_endian(const BIGNUM *number, size_t size)
{
	std::vector<uint8_t> out(size);
	if (number && BN_bn2binpad(number, out.data(), int(size)) < 0)
		out.clear();
	return out;
}

BIGNUM *number(const uint8_t *data, size_t size)
{
	return BN_bin2bn(data, int(size), nullptr);
}

std::vector<uint8_t> bn_param(EVP_PKEY *key, const char *name, size_t size)
{
	BIGNUM *value = nullptr;
	if (EVP_PKEY_get_bn_param(key, name, &value) != 1)
		return {};
	auto out = big_endian(value, size ? size : size_t(BN_num_bytes(value)));
	BN_clear_free(value);
	return out;
}

EVP_PKEY *from_parameters(const char *type, OSSL_PARAM_BLD *builder, int selection)
{
	OSSL_PARAM *parameters = OSSL_PARAM_BLD_to_param(builder);
	EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr);
	EVP_PKEY *key = nullptr;
	if (parameters && context && EVP_PKEY_fromdata_init(context) == 1)
		EVP_PKEY_fromdata(context, &key, selection, parameters);
	EVP_PKEY_CTX_free(context);
	OSSL_PARAM_free(parameters);
	return key;
}

// An elliptic-curve key from its coordinates and, for a private key, its scalar.
EVP_PKEY *ec_key(const std::string &group, const uint8_t *x, const uint8_t *y, size_t size, const uint8_t *d)
{
	OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
	EVP_PKEY *key = nullptr;
	BIGNUM *scalar = nullptr;
	if (group == "X25519") {
		OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, x, size);
		if (d)
			OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PRIV_KEY, d, size);
		key = from_parameters("X25519", builder, d ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY);
		OSSL_PARAM_BLD_free(builder);
		return key;
	}
	std::vector<uint8_t> point{0x04};
	point.insert(point.end(), x, x + size);
	point.insert(point.end(), y, y + size);
	OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, group.c_str(), 0);
	OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size());
	if (d) {
		scalar = number(d, size);
		OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, scalar);
	}
	key = from_parameters("EC", builder, d ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY);
	BN_clear_free(scalar);
	OSSL_PARAM_BLD_free(builder);
	return key;
}

std::string key_group(EVP_PKEY *key)
{
	if (EVP_PKEY_is_a(key, "X25519"))
		return "X25519";
	char name[64] = {};
	size_t length = 0;
	if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, name, sizeof(name), &length) != 1)
		return {};
	return name;
}

std::optional<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> ec_point(EVP_PKEY *key, size_t size)
{
	std::vector<uint8_t> encoded(1 + 2 * size + 8);
	size_t length = 0;
	if (EVP_PKEY_is_a(key, "X25519")) {
		if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, encoded.data(), encoded.size(), &length) != 1)
			return std::nullopt;
		encoded.resize(length);
		return std::pair{encoded, std::vector<uint8_t>(size)};
	}
	EVP_PKEY_set_utf8_string_param(key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, "uncompressed");
	if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, encoded.data(), encoded.size(), &length) != 1 || length != 1 + 2 * size)
		return std::nullopt;
	return std::pair{std::vector<uint8_t>(encoded.begin() + 1, encoded.begin() + 1 + size),
		std::vector<uint8_t>(encoded.begin() + 1 + size, encoded.begin() + 1 + 2 * size)};
}

uint32_t ec_magic(Kind kind, const std::string &group, bool private_key, bool generic)
{
	if (generic || group == "X25519" || group == "secp256k1")
		return kind == Kind::ecdh ? (private_key ? magic_ecdh_private_generic : magic_ecdh_public_generic)
		                          : (private_key ? magic_ecdsa_private_generic : magic_ecdsa_public_generic);
	const uint32_t index = group == "prime256v1" ? 1 : group == "secp384r1" ? 3 : 5;
	const uint32_t base = kind == Kind::ecdh ? 0x304b4345 : 0x30534345; // ECK0, ECS0
	return base + index + (private_key ? 1 : 0);
}

EVP_PKEY *rsa_key(const std::vector<uint8_t> &blob, bool private_key)
{
	if (blob.size() < 24)
		return nullptr;
	uint32_t header[6];
	std::memcpy(header, blob.data(), 24);
	const size_t exponent = header[2], modulus = header[3], prime1 = header[4], prime2 = header[5];
	if (blob.size() < 24 + exponent + modulus + (private_key ? prime1 + prime2 : 0))
		return nullptr;
	const uint8_t *at = blob.data() + 24;
	BIGNUM *e = number(at, exponent), *n = number(at + exponent, modulus), *p = nullptr, *q = nullptr, *d = nullptr;
	OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
	OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_N, n);
	OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_E, e);
	BN_CTX *bn = BN_CTX_new();
	if (private_key && prime1 && prime2) {
		// The private blob holds the primes; the private exponent follows from them, or comes after them in a full blob.
		p = number(at + exponent + modulus, prime1);
		q = number(at + exponent + modulus + prime1, prime2);
		if (header[0] == magic_rsa_full && blob.size() >= 24 + exponent + modulus * 2 + prime1 * 3 + prime2 * 2) {
			d = number(at + exponent + modulus + prime1 * 2 + prime2 * 2 + prime1, modulus);
		} else {
			BIGNUM *p1 = BN_dup(p), *q1 = BN_dup(q), *phi = BN_new();
			BN_sub_word(p1, 1);
			BN_sub_word(q1, 1);
			BN_mul(phi, p1, q1, bn);
			d = BN_mod_inverse(nullptr, e, phi, bn);
			BN_free(p1);
			BN_free(q1);
			BN_free(phi);
		}
		OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_D, d);
		OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
		OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
	}
	EVP_PKEY *key = from_parameters("RSA", builder, private_key ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY);
	OSSL_PARAM_BLD_free(builder);
	BN_CTX_free(bn);
	BN_free(e);
	BN_free(n);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(d);
	return key;
}

std::vector<uint8_t> rsa_blob(EVP_PKEY *key, uint32_t magic)
{
	const auto n = bn_param(key, OSSL_PKEY_PARAM_RSA_N, 0), e = bn_param(key, OSSL_PKEY_PARAM_RSA_E, 0);
	std::vector<uint8_t> p, q;
	if (magic != magic_rsa_public) {
		p = bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR1, 0);
		q = bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR2, 0);
		if (p.empty() || q.empty())
			return {};
	}
	const uint32_t header[6] = {magic, uint32_t(EVP_PKEY_get_bits(key)), uint32_t(e.size()), uint32_t(n.size()), uint32_t(p.size()), uint32_t(q.size())};
	std::vector<uint8_t> blob(reinterpret_cast<const uint8_t *>(header), reinterpret_cast<const uint8_t *>(header) + 24);
	blob.insert(blob.end(), e.begin(), e.end());
	blob.insert(blob.end(), n.begin(), n.end());
	blob.insert(blob.end(), p.begin(), p.end());
	blob.insert(blob.end(), q.begin(), q.end());
	if (magic == magic_rsa_full) {
		for (const char *name : {OSSL_PKEY_PARAM_RSA_EXPONENT1, OSSL_PKEY_PARAM_RSA_EXPONENT2}) {
			const auto value = bn_param(key, name, name == std::string_view(OSSL_PKEY_PARAM_RSA_EXPONENT1) ? p.size() : q.size());
			blob.insert(blob.end(), value.begin(), value.end());
		}
		const auto coefficient = bn_param(key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, p.size()), d = bn_param(key, OSSL_PKEY_PARAM_RSA_D, n.size());
		blob.insert(blob.end(), coefficient.begin(), coefficient.end());
		blob.insert(blob.end(), d.begin(), d.end());
	}
	return blob;
}

EVP_PKEY *dh_key(const std::vector<uint8_t> &parameters, const uint8_t *public_value, const uint8_t *private_value)
{
	const size_t size = parameters.size() / 2;
	BIGNUM *p = number(parameters.data(), size), *g = number(parameters.data() + size, size), *y = nullptr, *x = nullptr;
	OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
	OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_FFC_P, p);
	OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_FFC_G, g);
	int selection = EVP_PKEY_KEY_PARAMETERS;
	if (public_value) {
		y = number(public_value, size);
		OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PUB_KEY, y);
		selection = EVP_PKEY_PUBLIC_KEY;
	}
	if (private_value) {
		x = number(private_value, size);
		OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, x);
		selection = EVP_PKEY_KEYPAIR;
	}
	EVP_PKEY *key = from_parameters("DH", builder, selection);
	OSSL_PARAM_BLD_free(builder);
	BN_free(p);
	BN_free(g);
	BN_free(y);
	BN_clear_free(x);
	return key;
}

// A DH parameter blob (header, then p and g) as the two numbers.
std::optional<std::vector<uint8_t>> dh_parameters(const std::vector<uint8_t> &blob)
{
	if (blob.size() < 12)
		return std::nullopt;
	uint32_t header[3];
	std::memcpy(header, blob.data(), 12);
	if (header[1] != magic_dh_parameters || header[0] != blob.size() || blob.size() != 12 + 2 * size_t(header[2]))
		return std::nullopt;
	return std::vector<uint8_t>(blob.begin() + 12, blob.end());
}

const EVP_CIPHER *cipher_for(const Key &key, bool &stream)
{
	const auto &mode = key.chaining;
	const bool aes = key.algorithm->name == u"AES";
	const size_t bits = key.secret.size() * 8;
	std::string name;
	stream = false;
	if (aes) {
		name = "AES-" + std::to_string(bits) + "-";
		if (mode == u"ChainingModeCBC")
			name += "CBC";
		else if (mode == u"ChainingModeECB")
			name += "ECB";
		else if (mode == u"ChainingModeCFB")
			name += key.message_block == 16 ? "CFB" : "CFB8", stream = true;
		else if (mode == u"ChainingModeGCM")
			name += "GCM", stream = true;
		else
			return nullptr;
	} else if (key.algorithm->name == u"3DES") {
		name = mode == u"ChainingModeECB" ? "DES-EDE3-ECB" : mode == u"ChainingModeCFB" ? "DES-EDE3-CFB8" : "DES-EDE3-CBC";
		stream = mode == u"ChainingModeCFB";
	} else {
		return nullptr;
	}
	return EVP_get_cipherbyname(name.c_str());
}

}

void register_bcrypt_api(ApiRegistry &registry, KernelContext &context)
{
	table().allocate = [&context] { return context.allocator.allocate(16, true); };
	table().release = [&context](uint64_t handle) { context.allocator.release(handle); };
	const auto trace = [](const char *format, auto... values) {
		if (tracing())
			std::fprintf(stderr, format, values...);
	};
	// Answers the size a buffer must have, writes the value when the buffer holds it, and reports the size either way.
	const auto answer = [](ApiCall &call, uint64_t buffer, uint32_t capacity, uint64_t result, const std::vector<uint8_t> &value) {
		if (result)
			call.store<uint32_t>(result, uint32_t(value.size()));
		if (!buffer)
			return status_success;
		if (capacity < value.size())
			return status_buffer_too_small;
		call.write(buffer, value);
		return status_success;
	};
	const auto dword = [](uint32_t value) {
		return std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(&value), reinterpret_cast<const uint8_t *>(&value) + 4);
	};
	const auto wide_value = [](std::u16string_view text) {
		std::vector<uint8_t> out;
		for (const auto character : text) {
			out.push_back(uint8_t(character));
			out.push_back(uint8_t(character >> 8));
		}
		out.insert(out.end(), {0, 0});
		return out;
	};

	registry.add("BCryptOpenAlgorithmProvider", 4, [trace](ApiCall &call) {
		const auto name = call[1] ? call.wide(call[1], 64) : std::u16string();
		trace("bcrypt: open %s flags %x\n", to_utf8(name).c_str(), call.u32(3));
		if (!call[0] || name.empty()) {
			call.ret(status_invalid_parameter);
			return;
		}
		auto algorithm = make_algorithm(name, call.u32(3));
		if (!algorithm) {
			if (std::getenv("RAVEN_TRACE_FAIL"))
				std::fprintf(stderr, "raven: bcrypt algorithm %s is not supported\n", to_utf8(name).c_str());
			call.store_pointer(call[0], 0);
			call.ret(status_not_found);
			return;
		}
		const auto added = table().add(algorithm);
		if (!added) {
			call.ret(status_no_memory);
			return;
		}
		call.store_pointer(call[0], added);
		call.ret(status_success);
	});
	registry.add("BCryptCloseAlgorithmProvider", 2, [](ApiCall &call) {
		call.ret(pseudo_algorithm(call[0]) || table().remove(call[0]) ? status_success : status_invalid_handle);
	});

	registry.add("BCryptGetProperty", 6, [answer, dword, wide_value, trace](ApiCall &call) {
		const auto property = call[1] ? call.wide(call[1], 64) : std::u16string();
		const uint64_t buffer = call[2], result = call[4];
		const uint32_t capacity = call.u32(3);
		std::shared_ptr<Algorithm> algorithm = algorithm_of(call[0]);
		std::shared_ptr<Key> key;
		std::shared_ptr<Hash> hash;
		if (!algorithm) {
			if ((key = table().get<Key>(call[0])))
				algorithm = key->algorithm;
			else if ((hash = table().get<Hash>(call[0])))
				algorithm = hash->algorithm;
		}
		trace("bcrypt: get property %s\n", to_utf8(property).c_str());
		if (!algorithm) {
			call.ret(status_invalid_handle);
			return;
		}
		std::optional<std::vector<uint8_t>> value;
		const auto chaining = key ? key->chaining : algorithm->chaining;
		const auto curve = key && !key->curve.empty() ? key->curve : algorithm->curve;
		if (property == u"ObjectLength" || property == u"HashObjectLength" || property == u"KeyObjectLength")
			value = dword(64);
		else if (property == u"HashDigestLength" && algorithm->kind == Kind::hash)
			value = dword(uint32_t(digest_size(*algorithm)));
		else if (property == u"HashBlockLength" && algorithm->kind == Kind::hash)
			value = dword(uint32_t(digest_block(*algorithm)));
		else if (property == u"BlockLength" && algorithm->kind == Kind::cipher)
			value = dword(chaining == u"ChainingModeGCM" ? 16 : uint32_t(cipher_block(*algorithm)));
		else if (property == u"BlockLength" && algorithm->kind == Kind::hash)
			value = dword(uint32_t(digest_block(*algorithm)));
		else if (property == u"ChainingMode" && algorithm->kind == Kind::cipher)
			value = wide_value(chaining);
		else if (property == u"AlgorithmName")
			value = wide_value(algorithm->name);
		else if (property == u"KeyLengths" && algorithm->kind == Kind::cipher) {
			const uint32_t lengths[3] = {algorithm->name == u"AES" ? 128u : 192u, algorithm->name == u"AES" ? 256u : 192u, algorithm->name == u"AES" ? 64u : 0u};
			value = std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(lengths), reinterpret_cast<const uint8_t *>(lengths) + 12);
		} else if (property == u"AuthTagLength" && algorithm->kind == Kind::cipher) {
			const uint32_t lengths[3] = {12, 16, 1};
			value = std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(lengths), reinterpret_cast<const uint8_t *>(lengths) + 12);
		} else if (property == u"MessageBlockLength" && algorithm->kind == Kind::cipher)
			value = dword(key ? key->message_block : algorithm->message_block);
		else if ((property == u"KeyLength" || property == u"KeyStrength") && key) {
			if (key->pair)
				value = dword(uint32_t(EVP_PKEY_get_bits(key->pair)));
			else if (key->bits)
				value = dword(key->bits);
			else
				value = dword(uint32_t(key->secret.size() * 8));
		} else if (property == u"ECCCurveName" && !curve.empty())
			value = wide_value(curve_name(curve));
		else if (property == u"SignatureLength" && key && key->pair)
			value = dword(algorithm->kind == Kind::ecdsa ? uint32_t(2 * field_bytes(curve)) : uint32_t(EVP_PKEY_get_size(key->pair)));
		else if (property == u"KeyLengths" && (algorithm->kind == Kind::ecdh || algorithm->kind == Kind::ecdsa)) {
			const uint32_t bits = curve == "secp384r1" ? 384 : curve == "secp521r1" ? 521 : 256;
			const uint32_t lengths[3] = {bits, bits, 0};
			value = std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(lengths), reinterpret_cast<const uint8_t *>(lengths) + 12);
		} else if (property == u"KeyLengths" && (algorithm->kind == Kind::rsa || algorithm->kind == Kind::dh)) {
			const uint32_t lengths[3] = {512, algorithm->kind == Kind::rsa ? 16384u : 4096u, 64};
			value = std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(lengths), reinterpret_cast<const uint8_t *>(lengths) + 12);
		} else if (property == u"PaddingSchemes" && algorithm->kind == Kind::rsa)
			value = dword(pad_none | pad_pkcs1 | pad_oaep | pad_pss);
		if (!value) {
			if (std::getenv("RAVEN_TRACE_FAIL"))
				std::fprintf(stderr, "raven: bcrypt property %s of %s is not supported\n", to_utf8(property).c_str(), to_utf8(algorithm->name).c_str());
			call.ret(status_not_supported);
			return;
		}
		call.ret(answer(call, buffer, capacity, result, *value));
	});

	registry.add("BCryptSetProperty", 5, [trace](ApiCall &call) {
		const auto property = call[1] ? call.wide(call[1], 64) : std::u16string();
		const auto bytes = call[2] ? call.read(call[2], call.u32(3)) : std::vector<uint8_t>();
		std::u16string text;
		for (size_t index = 0; index + 1 < bytes.size(); index += 2) {
			const char16_t character = char16_t(bytes[index] | bytes[index + 1] << 8);
			if (!character)
				break;
			text.push_back(character);
		}
		trace("bcrypt: set property %s %s\n", to_utf8(property).c_str(), to_utf8(text).c_str());
		auto algorithm = table().get<Algorithm>(call[0]);
		auto key = algorithm ? nullptr : table().get<Key>(call[0]);
		if (auto hash = algorithm || key ? nullptr : table().get<Hash>(call[0])) {
			// The nonce of an AES-GMAC hash, which starts it over.
			if (property != u"IV" || !hash->algorithm->gmac || bytes.empty()) {
				call.ret(status_not_supported);
				return;
			}
			hash->nonce = bytes;
			call.ret(start_hash(*hash) ? status_success : status_invalid_parameter);
			return;
		}
		if (!algorithm && !key) {
			call.ret(pseudo_algorithm(call[0]) ? status_invalid_parameter : status_invalid_handle);
			return;
		}
		if (property == u"ChainingMode") {
			if (text != u"ChainingModeCBC" && text != u"ChainingModeECB" && text != u"ChainingModeCFB" && text != u"ChainingModeGCM" &&
				text != u"ChainingModeN/A") {
				call.ret(status_not_supported);
				return;
			}
			(algorithm ? algorithm->chaining : key->chaining) = text;
		} else if (property == u"ECCCurveName") {
			const auto group = curve_group(text);
			if (group.empty()) {
				call.ret(status_not_supported);
				return;
			}
			(algorithm ? algorithm->curve : key->curve) = group;
		} else if (property == u"DHParameters") {
			const auto parameters = dh_parameters(bytes);
			if (!parameters) {
				call.ret(status_invalid_parameter);
				return;
			}
			(algorithm ? algorithm->dh_parameters : key->dh_parameters) = *parameters;
		} else if (property == u"MessageBlockLength" && bytes.size() == 4) {
			uint32_t length;
			std::memcpy(&length, bytes.data(), 4);
			(algorithm ? algorithm->message_block : key->message_block) = length;
		} else {
			if (std::getenv("RAVEN_TRACE_FAIL"))
				std::fprintf(stderr, "raven: bcrypt property %s cannot be set\n", to_utf8(property).c_str());
			call.ret(status_not_supported);
			return;
		}
		call.ret(status_success);
	});

	// ---- hashes ----
	const auto create_hash = [](ApiCall &call, uint64_t algorithm_handle, uint64_t out, uint64_t secret, uint32_t secret_size) -> uint32_t {
		auto algorithm = algorithm_of(algorithm_handle);
		if (!algorithm || algorithm->kind != Kind::hash)
			return status_invalid_handle;
		auto hash = std::make_shared<Hash>();
		hash->algorithm = algorithm;
		if (secret && secret_size)
			hash->secret = call.read(secret, secret_size);
		if (!start_hash(*hash))
			return status_unsuccessful;
		if (!out)
			return status_invalid_parameter;
		const auto added = table().add(hash);
		if (!added)
			return status_no_memory;
		call.store_pointer(out, added);
		return status_success;
	};
	registry.add("BCryptCreateHash", 7, [create_hash](ApiCall &call) {
		call.ret(create_hash(call, call[0], call[1], call[4], call.u32(5)));
	});
	registry.add("BCryptCreateMultiHash", 8, [](ApiCall &call) { call.ret(status_not_supported); });
	registry.add("BCryptHashData", 4, [](ApiCall &call) {
		auto hash = table().get<Hash>(call[0]);
		if (!hash) {
			call.ret(status_invalid_handle);
			return;
		}
		call.ret(update_hash(*hash, call[1] ? call.read(call[1], call.u32(2)) : std::vector<uint8_t>()) ? status_success : status_unsuccessful);
	});
	// Finishing a hash leaves it ready to start over, which a reusable hash promises and a single-use one never uses.
	registry.add("BCryptFinishHash", 4, [](ApiCall &call) {
		auto hash = table().get<Hash>(call[0]);
		if (!hash) {
			call.ret(status_invalid_handle);
			return;
		}
		const size_t size = digest_size(*hash->algorithm);
		if (call.u32(2) != size) {
			call.ret(status_invalid_parameter);
			return;
		}
		const auto value = finish_hash(*hash);
		if (value.size() != size) {
			call.ret(status_unsuccessful);
			return;
		}
		call.write(call[1], value);
		start_hash(*hash);
		call.ret(status_success);
	});
	registry.add("BCryptDuplicateHash", 5, [](ApiCall &call) {
		auto hash = table().get<Hash>(call[0]);
		if (!hash || !call[1]) {
			call.ret(hash ? status_invalid_parameter : status_invalid_handle);
			return;
		}
		auto copy = std::make_shared<Hash>();
		copy->algorithm = hash->algorithm;
		copy->secret = hash->secret;
		copy->nonce = hash->nonce;
		if (hash->mac)
			copy->mac = EVP_MAC_CTX_dup(hash->mac);
		else {
			copy->digest = EVP_MD_CTX_new();
			EVP_MD_CTX_copy_ex(copy->digest, hash->digest);
		}
		const auto added = table().add(copy);
		if (!added) {
			call.ret(status_no_memory);
			return;
		}
		call.store_pointer(call[1], added);
		call.ret(status_success);
	});
	registry.add("BCryptDestroyHash", 1, [](ApiCall &call) { call.ret(table().remove(call[0]) ? status_success : status_invalid_handle); });
	registry.add("BCryptHash", 7, [](ApiCall &call) {
		auto algorithm = algorithm_of(call[0]);
		if (!algorithm || algorithm->kind != Kind::hash) {
			call.ret(status_invalid_handle);
			return;
		}
		Hash hash;
		hash.algorithm = algorithm;
		if (call[1] && call.u32(2))
			hash.secret = call.read(call[1], call.u32(2));
		if (!start_hash(hash) || !update_hash(hash, call[3] ? call.read(call[3], call.u32(4)) : std::vector<uint8_t>())) {
			call.ret(status_unsuccessful);
			return;
		}
		const auto value = finish_hash(hash);
		if (call.u32(6) != value.size()) {
			call.ret(status_invalid_parameter);
			return;
		}
		call.write(call[5], value);
		call.ret(status_success);
	});

	// ---- symmetric keys ----
	const auto symmetric_key = [](std::shared_ptr<Algorithm> algorithm, std::vector<uint8_t> secret) -> std::shared_ptr<Key> {
		const size_t size = secret.size();
		if (algorithm->name == u"AES" ? size != 16 && size != 24 && size != 32 : size != 24)
			return nullptr;
		auto key = std::make_shared<Key>();
		key->algorithm = algorithm;
		key->secret = std::move(secret);
		key->chaining = algorithm->chaining;
		key->message_block = algorithm->message_block;
		key->feedback.assign(cipher_block(*algorithm), 0);
		return key;
	};
	registry.add("BCryptGenerateSymmetricKey", 7, [symmetric_key](ApiCall &call) {
		auto algorithm = algorithm_of(call[0]);
		if (!algorithm || algorithm->kind != Kind::cipher) {
			call.ret(status_invalid_handle);
			return;
		}
		auto key = symmetric_key(algorithm, call.read(call[4], call.u32(5)));
		if (!key || !call[1]) {
			call.ret(status_invalid_parameter);
			return;
		}
		const auto added = table().add(key);
		if (!added) {
			call.ret(status_no_memory);
			return;
		}
		call.store_pointer(call[1], added);
		call.ret(status_success);
	});
	registry.add("BCryptDuplicateKey", 5, [](ApiCall &call) {
		auto key = table().get<Key>(call[0]);
		if (!key || !call[1]) {
			call.ret(key ? status_invalid_parameter : status_invalid_handle);
			return;
		}
		auto copy = std::make_shared<Key>(*key);
		if (key->pair) {
			EVP_PKEY_up_ref(key->pair);
			copy->pair = key->pair;
		}
		const auto added = table().add(copy);
		if (!added) {
			call.ret(status_no_memory);
			return;
		}
		call.store_pointer(call[1], added);
		call.ret(status_success);
	});
	registry.add("BCryptDestroyKey", 1, [](ApiCall &call) { call.ret(table().remove(call[0]) ? status_success : status_invalid_handle); });
	registry.add("BCryptDestroySecret", 1, [](ApiCall &call) { call.ret(table().remove(call[0]) ? status_success : status_invalid_handle); });

	// BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO: where its fields sit for a program of either width.
	struct AuthenticatedInfo {
		uint64_t nonce, nonce_size, data, data_size, tag, tag_size, flags;
	};
	const auto authenticated_info = [](ApiCall &call, uint64_t base) {
		const size_t width = call.pointer_width();
		AuthenticatedInfo at;
		at.nonce = base + 8;
		at.nonce_size = at.nonce + width;
		at.data = width == 8 ? base + 24 : base + 16;
		at.data_size = at.data + width;
		at.tag = width == 8 ? base + 40 : base + 24;
		at.tag_size = at.tag + width;
		at.flags = width == 8 ? base + 80 : base + 56;
		return at;
	};

	// Encrypting and decrypting with a symmetric key: the block modes chain through the IV the call passes, which comes back as the
	// feedback for the next call, as CNG updates it.
	const auto symmetric = [authenticated_info](ApiCall &call, Key &key, bool encrypt) -> uint32_t {
		const uint64_t input = call[1], padding_info = call[3], iv = call[4], output = call[6], result = call[8];
		const uint32_t input_size = call.u32(2), iv_size = call.u32(5), output_size = call.u32(7), flags = call.u32(9);
		bool stream = false;
		const EVP_CIPHER *cipher = cipher_for(key, stream);
		if (!cipher)
			return status_not_supported;
		const size_t block = cipher_block(*key.algorithm);
		const bool gcm = key.chaining == u"ChainingModeGCM";
		const bool padded = (flags & block_padding) && !stream;
		size_t needed = input_size;
		if (padded && encrypt)
			needed = (input_size / block + 1) * block;
		if (!stream && !padded && input_size % block)
			return status_invalid_buffer_size;
		if (!stream && padded && !encrypt && input_size % block)
			return status_invalid_buffer_size;
		if (!output) {
			if (result)
				call.store<uint32_t>(result, uint32_t(needed));
			return status_success;
		}
		if (output_size < (encrypt || !padded ? needed : input_size - block)) {
			if (result)
				call.store<uint32_t>(result, uint32_t(needed));
			return status_buffer_too_small;
		}
		const auto data = input && input_size ? call.read(input, input_size) : std::vector<uint8_t>();
		std::vector<uint8_t> vector, nonce, aad, tag;
		AuthenticatedInfo info{};
		if (gcm) {
			if (!padding_info)
				return status_invalid_parameter;
			info = authenticated_info(call, padding_info);
			if (call.load<uint32_t>(info.flags) & 1)
				return status_not_supported; // calls chained over one message
			nonce = call.read(call.load_pointer(info.nonce), call.load<uint32_t>(info.nonce_size));
			if (const auto pointer = call.load_pointer(info.data); pointer)
				aad = call.read(pointer, call.load<uint32_t>(info.data_size));
			tag.resize(call.load<uint32_t>(info.tag_size));
			if (!encrypt)
				tag = call.read(call.load_pointer(info.tag), tag.size());
		} else if (key.chaining != u"ChainingModeECB") {
			vector = iv ? call.read(iv, iv_size) : key.feedback;
			if (vector.size() != block)
				return status_invalid_parameter;
		}
		EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
		std::vector<uint8_t> out(data.size() + block * 2);
		int length = 0, tail = 0;
		bool good = EVP_CipherInit_ex(context, cipher, nullptr, nullptr, nullptr, encrypt) == 1;
		if (gcm)
			good = good && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, int(nonce.size()), nullptr) == 1;
		good = good && EVP_CipherInit_ex(context, nullptr, nullptr, key.secret.data(), gcm ? nonce.data() : vector.empty() ? nullptr : vector.data(),
			encrypt) == 1;
		EVP_CIPHER_CTX_set_padding(context, padded ? 1 : 0);
		if (gcm && !aad.empty())
			good = good && EVP_CipherUpdate(context, nullptr, &length, aad.data(), int(aad.size())) == 1;
		if (gcm && !encrypt)
			good = good && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, int(tag.size()), tag.data()) == 1;
		good = good && EVP_CipherUpdate(context, out.data(), &length, data.data(), int(data.size())) == 1;
		const bool finished = good && EVP_CipherFinal_ex(context, out.data() + length, &tail) == 1;
		if (gcm && encrypt && finished)
			good = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, int(tag.size()), tag.data()) == 1;
		EVP_CIPHER_CTX_free(context);
		if (!good)
			return status_unsuccessful;
		if (!finished)
			return gcm ? status_auth_tag_mismatch : status_data_error;
		out.resize(size_t(length + tail));
		call.write(output, out);
		if (result)
			call.store<uint32_t>(result, uint32_t(out.size()));
		if (gcm && encrypt)
			call.write(call.load_pointer(info.tag), tag);
		// The feedback: the last block of ciphertext, or for the byte-wise feedback mode the last bytes of all ciphertext so far.
		if (!gcm && key.chaining != u"ChainingModeECB") {
			const auto &ciphertext = encrypt ? out : data;
			std::vector<uint8_t> feedback = vector;
			feedback.insert(feedback.end(), ciphertext.begin(), ciphertext.end());
			if (encrypt && padded)
				feedback.assign(out.end() - block, out.end());
			feedback.erase(feedback.begin(), feedback.end() - block);
			if (iv)
				call.write(iv, feedback);
			else
				key.feedback = feedback;
		}
		return status_success;
	};

	// ---- asymmetric keys ----
	const auto rsa_padding = [](ApiCall &call, EVP_PKEY_CTX *context, uint64_t info, uint32_t flags, bool sign) -> bool {
		if (flags & pad_pkcs1) {
			if (EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PADDING) != 1)
				return false;
			if (sign && info) {
				const auto pointer = call.load_pointer(info);
				const auto name = pointer ? digest_name(call.wide(pointer, 32)) : std::string();
				if (!name.empty() && EVP_PKEY_CTX_set_signature_md(context, EVP_get_digestbyname(name.c_str())) != 1)
					return false;
			}
			return true;
		}
		if (flags & pad_pss) {
			const auto name = digest_name(call.wide(call.load_pointer(info), 32));
			const auto salt = call.load<uint32_t>(info + call.pointer_width());
			return !name.empty() && EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING) == 1 &&
				EVP_PKEY_CTX_set_signature_md(context, EVP_get_digestbyname(name.c_str())) == 1 && EVP_PKEY_CTX_set_rsa_pss_saltlen(context, int(salt)) == 1;
		}
		if (flags & pad_oaep) {
			const auto name = digest_name(call.wide(call.load_pointer(info), 32));
			const auto label_at = call.load_pointer(info + call.pointer_width());
			const auto label_size = call.load<uint32_t>(info + 2 * call.pointer_width());
			if (name.empty() || EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING) != 1 ||
				EVP_PKEY_CTX_set_rsa_oaep_md(context, EVP_get_digestbyname(name.c_str())) != 1)
				return false;
			if (label_at && label_size) {
				const auto label = call.read(label_at, label_size);
				void *copy = OPENSSL_memdup(label.data(), label.size());
				return EVP_PKEY_CTX_set0_rsa_oaep_label(context, copy, int(label.size())) == 1;
			}
			return true;
		}
		return EVP_PKEY_CTX_set_rsa_padding(context, RSA_NO_PADDING) == 1;
	};
	const auto asymmetric = [rsa_padding](ApiCall &call, Key &key, bool encrypt) -> uint32_t {
		if (key.algorithm->kind != Kind::rsa || !key.pair)
			return status_not_supported;
		const auto data = call.read(call[1], call.u32(2));
		EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(nullptr, key.pair, nullptr);
		size_t length = 0;
		bool good = context && (encrypt ? EVP_PKEY_encrypt_init(context) : EVP_PKEY_decrypt_init(context)) == 1 &&
			rsa_padding(call, context, call[3], call.u32(9), false);
		good = good && (encrypt ? EVP_PKEY_encrypt(context, nullptr, &length, data.data(), data.size())
		                        : EVP_PKEY_decrypt(context, nullptr, &length, data.data(), data.size())) == 1;
		if (!good) {
			EVP_PKEY_CTX_free(context);
			return status_invalid_parameter;
		}
		if (!call[6]) {
			EVP_PKEY_CTX_free(context);
			if (call[8])
				call.store<uint32_t>(call[8], uint32_t(length));
			return status_success;
		}
		std::vector<uint8_t> out(length);
		good = (encrypt ? EVP_PKEY_encrypt(context, out.data(), &length, data.data(), data.size())
		                : EVP_PKEY_decrypt(context, out.data(), &length, data.data(), data.size())) == 1;
		EVP_PKEY_CTX_free(context);
		if (!good)
			return status_data_error;
		out.resize(length);
		if (call.u32(7) < out.size())
			return status_buffer_too_small;
		call.write(call[6], out);
		if (call[8])
			call.store<uint32_t>(call[8], uint32_t(out.size()));
		return status_success;
	};
	registry.add("BCryptEncrypt", 10, [symmetric, asymmetric](ApiCall &call) {
		auto key = table().get<Key>(call[0]);
		call.ret(!key ? status_invalid_handle : key->algorithm->kind == Kind::cipher ? symmetric(call, *key, true) : asymmetric(call, *key, true));
	});
	registry.add("BCryptDecrypt", 10, [symmetric, asymmetric](ApiCall &call) {
		auto key = table().get<Key>(call[0]);
		call.ret(!key ? status_invalid_handle : key->algorithm->kind == Kind::cipher ? symmetric(call, *key, false) : asymmetric(call, *key, false));
	});

	registry.add("BCryptGenerateKeyPair", 4, [trace](ApiCall &call) {
		auto algorithm = algorithm_of(call[0]);
		trace("bcrypt: generate key pair of %u bits\n", call.u32(2));
		if (!algorithm || algorithm->kind == Kind::hash || algorithm->kind == Kind::cipher || algorithm->kind == Kind::rng || !call[1]) {
			call.ret(algorithm ? status_invalid_parameter : status_invalid_handle);
			return;
		}
		auto key = std::make_shared<Key>();
		key->algorithm = algorithm;
		key->bits = call.u32(2);
		key->curve = algorithm->curve;
		key->dh_parameters = algorithm->dh_parameters;
		if (key->curve.empty() && (algorithm->kind == Kind::ecdh || algorithm->kind == Kind::ecdsa))
			key->curve = key->bits == 384 ? "secp384r1" : key->bits == 521 ? "secp521r1" : key->bits == 255 ? "X25519" : "prime256v1";
		const auto added = table().add(key);
		if (!added) {
			call.ret(status_no_memory);
			return;
		}
		call.store_pointer(call[1], added);
		call.ret(status_success);
	});
	registry.add("BCryptFinalizeKeyPair", 2, [](ApiCall &call) {
		auto key = table().get<Key>(call[0]);
		if (!key) {
			call.ret(status_invalid_handle);
			return;
		}
		if (key->pair) {
			call.ret(status_invalid_parameter);
			return;
		}
		EVP_PKEY_CTX *context = nullptr;
		EVP_PKEY *domain = nullptr;
		switch (key->algorithm->kind) {
		case Kind::rsa:
			context = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
			if (context && EVP_PKEY_keygen_init(context) == 1)
				EVP_PKEY_CTX_set_rsa_keygen_bits(context, int(key->bits));
			break;
		case Kind::ecdh:
		case Kind::ecdsa:
			if (key->curve == "X25519") {
				context = EVP_PKEY_CTX_new_from_name(nullptr, "X25519", nullptr);
				if (context)
					EVP_PKEY_keygen_init(context);
			} else {
				context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
				if (context && EVP_PKEY_keygen_init(context) == 1)
					EVP_PKEY_CTX_set_group_name(context, key->curve.c_str());
			}
			break;
		case Kind::dh:
			if (key->dh_parameters.size() != key->bits / 4) {
				call.ret(status_invalid_parameter);
				return;
			}
			domain = dh_key(key->dh_parameters, nullptr, nullptr);
			context = domain ? EVP_PKEY_CTX_new_from_pkey(nullptr, domain, nullptr) : nullptr;
			if (context)
				EVP_PKEY_keygen_init(context);
			break;
		default:
			break;
		}
		const bool made = context && EVP_PKEY_generate(context, &key->pair) == 1;
		EVP_PKEY_CTX_free(context);
		EVP_PKEY_free(domain);
		call.ret(made ? status_success : status_unsuccessful);
	});

	registry.add("BCryptExportKey", 7, [answer, trace](ApiCall &call) {
		auto key = table().get<Key>(call[0]);
		const auto type = call[2] ? call.wide(call[2], 64) : std::u16string();
		trace("bcrypt: export %s\n", to_utf8(type).c_str());
		if (!key) {
			call.ret(status_invalid_handle);
			return;
		}
		std::vector<uint8_t> blob;
		const auto kind = key->algorithm->kind;
		const bool private_blob = type == u"ECCPRIVATEBLOB" || type == u"RSAPRIVATEBLOB" || type == u"RSAFULLPRIVATEBLOB" || type == u"DHPRIVATEBLOB";
		if (kind == Kind::cipher && (type == u"KeyDataBlob" || type == u"OpaqueKeyBlob")) {
			const uint32_t header[3] = {0x4d42444b, 1, uint32_t(key->secret.size())}; // KDBM, version 1
			blob.assign(reinterpret_cast<const uint8_t *>(header), reinterpret_cast<const uint8_t *>(header) + 12);
			blob.insert(blob.end(), key->secret.begin(), key->secret.end());
		} else if (!key->pair) {
			call.ret(status_invalid_handle);
			return;
		} else if ((kind == Kind::ecdh || kind == Kind::ecdsa) && (type == u"ECCPUBLICBLOB" || type == u"ECCPRIVATEBLOB")) {
			const auto group = key_group(key->pair);
			const size_t size = field_bytes(group);
			const auto point = ec_point(key->pair, size);
			if (!point) {
				call.ret(status_unsuccessful);
				return;
			}
			const uint32_t header[2] = {ec_magic(kind, group, private_blob, key->algorithm->curve.empty()), uint32_t(size)};
			blob.assign(reinterpret_cast<const uint8_t *>(header), reinterpret_cast<const uint8_t *>(header) + 8);
			blob.insert(blob.end(), point->first.begin(), point->first.end());
			blob.insert(blob.end(), point->second.begin(), point->second.end());
			if (private_blob) {
				std::vector<uint8_t> d(size);
				size_t length = 0;
				if (group == "X25519")
					EVP_PKEY_get_octet_string_param(key->pair, OSSL_PKEY_PARAM_PRIV_KEY, d.data(), d.size(), &length);
				else
					d = bn_param(key->pair, OSSL_PKEY_PARAM_PRIV_KEY, size);
				blob.insert(blob.end(), d.begin(), d.end());
			}
		} else if (kind == Kind::rsa && (type == u"RSAPUBLICBLOB" || private_blob)) {
			blob = rsa_blob(key->pair, type == u"RSAPUBLICBLOB" ? magic_rsa_public : type == u"RSAPRIVATEBLOB" ? magic_rsa_private : magic_rsa_full);
		} else if (kind == Kind::dh && (type == u"DHPUBLICBLOB" || type == u"DHPRIVATEBLOB")) {
			const size_t size = key->dh_parameters.size() / 2;
			const uint32_t header[2] = {private_blob ? magic_dh_private : magic_dh_public, uint32_t(size)};
			blob.assign(reinterpret_cast<const uint8_t *>(header), reinterpret_cast<const uint8_t *>(header) + 8);
			blob.insert(blob.end(), key->dh_parameters.begin(), key->dh_parameters.end());
			const auto y = bn_param(key->pair, OSSL_PKEY_PARAM_PUB_KEY, size);
			blob.insert(blob.end(), y.begin(), y.end());
			if (private_blob) {
				const auto x = bn_param(key->pair, OSSL_PKEY_PARAM_PRIV_KEY, size);
				blob.insert(blob.end(), x.begin(), x.end());
			}
		} else {
			if (std::getenv("RAVEN_TRACE_FAIL"))
				std::fprintf(stderr, "raven: bcrypt export %s is not supported\n", to_utf8(type).c_str());
			call.ret(status_not_supported);
			return;
		}
		if (blob.empty()) {
			call.ret(status_unsuccessful);
			return;
		}
		call.ret(answer(call, call[3], call.u32(4), call[5], blob));
	});

	registry.add("BCryptImportKeyPair", 7, [trace](ApiCall &call) {
		auto algorithm = algorithm_of(call[0]);
		const auto type = call[2] ? call.wide(call[2], 64) : std::u16string();
		trace("bcrypt: import %s\n", to_utf8(type).c_str());
		if (!algorithm || !call[3]) {
			call.ret(algorithm ? status_invalid_parameter : status_invalid_handle);
			return;
		}
		const auto blob = call.read(call[4], call.u32(5));
		auto key = std::make_shared<Key>();
		key->algorithm = algorithm;
		if (blob.size() < 8) {
			call.ret(status_invalid_parameter);
			return;
		}
		uint32_t header[2];
		std::memcpy(header, blob.data(), 8);
		if ((algorithm->kind == Kind::ecdh || algorithm->kind == Kind::ecdsa) && (type == u"ECCPUBLICBLOB" || type == u"ECCPRIVATEBLOB")) {
			const size_t size = header[1];
			const bool private_blob = type == u"ECCPRIVATEBLOB";
			std::string group = algorithm->curve;
			if (group.empty())
				group = size == 32 ? (header[0] == magic_ecdh_public_generic || header[0] == magic_ecdh_private_generic ? "X25519" : "prime256v1")
				                   : size == 48 ? "secp384r1" : "secp521r1";
			if (field_bytes(group) != size || blob.size() < 8 + size * (private_blob ? 3 : 2)) {
				call.ret(status_invalid_parameter);
				return;
			}
			key->curve = group;
			key->pair = ec_key(group, blob.data() + 8, blob.data() + 8 + size, size, private_blob ? blob.data() + 8 + 2 * size : nullptr);
		} else if (algorithm->kind == Kind::rsa && (type == u"RSAPUBLICBLOB" || type == u"RSAPRIVATEBLOB" || type == u"RSAFULLPRIVATEBLOB")) {
			key->pair = rsa_key(blob, type != u"RSAPUBLICBLOB");
		} else if (algorithm->kind == Kind::dh && (type == u"DHPUBLICBLOB" || type == u"DHPRIVATEBLOB")) {
			const size_t size = header[1];
			const bool private_blob = type == u"DHPRIVATEBLOB";
			if (blob.size() < 8 + size * (private_blob ? 4 : 3)) {
				call.ret(status_invalid_parameter);
				return;
			}
			key->dh_parameters.assign(blob.begin() + 8, blob.begin() + 8 + 2 * size);
			key->bits = uint32_t(size * 8);
			key->pair = dh_key(key->dh_parameters, blob.data() + 8 + 2 * size, private_blob ? blob.data() + 8 + 3 * size : nullptr);
		} else {
			if (std::getenv("RAVEN_TRACE_FAIL"))
				std::fprintf(stderr, "raven: bcrypt import %s is not supported\n", to_utf8(type).c_str());
			call.ret(status_not_supported);
			return;
		}
		if (!key->pair) {
			call.ret(status_invalid_parameter);
			return;
		}
		const auto added = table().add(key);
		if (!added) {
			call.ret(status_no_memory);
			return;
		}
		call.store_pointer(call[3], added);
		call.ret(status_success);
	});

	registry.add("BCryptImportKey", 9, [symmetric_key, trace](ApiCall &call) {
		auto algorithm = algorithm_of(call[0]);
		const auto type = call[2] ? call.wide(call[2], 64) : std::u16string();
		trace("bcrypt: import key %s\n", to_utf8(type).c_str());
		if (!algorithm || algorithm->kind != Kind::cipher || !call[3]) {
			call.ret(algorithm ? status_invalid_parameter : status_invalid_handle);
			return;
		}
		const auto blob = call.read(call[6], call.u32(7));
		uint32_t header[3] = {};
		if (type != u"KeyDataBlob" || blob.size() < 12 || (std::memcpy(header, blob.data(), 12), header[0] != 0x4d42444b) || blob.size() < 12 + size_t(header[2])) {
			call.ret(status_not_supported);
			return;
		}
		auto key = symmetric_key(algorithm, std::vector<uint8_t>(blob.begin() + 12, blob.begin() + 12 + header[2]));
		if (!key) {
			call.ret(status_invalid_parameter);
			return;
		}
		const auto added = table().add(key);
		if (!added) {
			call.ret(status_no_memory);
			return;
		}
		call.store_pointer(call[3], added);
		call.ret(status_success);
	});

	registry.add("BCryptSecretAgreement", 4, [](ApiCall &call) {
		auto own = table().get<Key>(call[0]), peer = table().get<Key>(call[1]);
		if (!own || !peer || !own->pair || !peer->pair || !call[2]) {
			call.ret(own && peer ? status_invalid_parameter : status_invalid_handle);
			return;
		}
		EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(nullptr, own->pair, nullptr);
		size_t length = 0;
		bool good = context && EVP_PKEY_derive_init(context) == 1;
		if (good && own->algorithm->kind == Kind::dh)
			EVP_PKEY_CTX_set_dh_pad(context, 1);
		good = good && EVP_PKEY_derive_set_peer(context, peer->pair) == 1 && EVP_PKEY_derive(context, nullptr, &length) == 1;
		auto secret = std::make_shared<Secret>();
		secret->value.resize(length);
		good = good && EVP_PKEY_derive(context, secret->value.data(), &length) == 1;
		EVP_PKEY_CTX_free(context);
		if (!good) {
			call.ret(status_invalid_parameter);
			return;
		}
		secret->value.resize(length);
		// X25519 gives its secret in little-endian order; the big-endian convention here keeps the raw form below its usual one.
		if (own->curve == "X25519")
			std::reverse(secret->value.begin(), secret->value.end());
		const auto added = table().add(secret);
		if (!added) {
			call.ret(status_no_memory);
			return;
		}
		call.store_pointer(call[2], added);
		call.ret(status_success);
	});

	// BCryptBufferDesc: version, count, then the buffers, each a size, a type and a pointer.
	const auto parameter_list = [](ApiCall &call, uint64_t list) {
		std::map<uint32_t, std::vector<uint8_t>> parameters;
		if (!list)
			return parameters;
		const uint32_t count = call.load<uint32_t>(list + 4);
		const uint64_t buffers = call.load_pointer(list + 8);
		const size_t stride = 8 + call.pointer_width();
		for (uint32_t index = 0; index < count && index < 64; ++index) {
			const uint64_t at = buffers + index * stride;
			const uint32_t size = call.load<uint32_t>(at), type = call.load<uint32_t>(at + 4);
			const uint64_t data = call.load_pointer(at + 8);
			auto &value = parameters[type];
			if (data && size)
				value = call.read(data, size);
		}
		return parameters;
	};
	const auto parameter_name = [](const std::vector<uint8_t> &bytes) {
		std::u16string text;
		for (size_t index = 0; index + 1 < bytes.size(); index += 2) {
			const char16_t character = char16_t(bytes[index] | bytes[index + 1] << 8);
			if (!character)
				break;
			text.push_back(character);
		}
		return text;
	};
	registry.add("BCryptDeriveKey", 7, [parameter_list, parameter_name, answer, trace](ApiCall &call) {
		auto secret = table().get<Secret>(call[0]);
		const auto kdf = call[1] ? call.wide(call[1], 64) : std::u16string();
		trace("bcrypt: derive %s\n", to_utf8(kdf).c_str());
		if (!secret) {
			call.ret(status_invalid_handle);
			return;
		}
		const auto parameters = parameter_list(call, call[2]);
		const auto parameter = [&](uint32_t type) {
			const auto found = parameters.find(type);
			return found == parameters.end() ? std::vector<uint8_t>() : found->second;
		};
		std::vector<uint8_t> derived;
		if (kdf == u"TRUNCATE") {
			// The raw secret, which CNG gives in little-endian order.
			derived.assign(secret->value.rbegin(), secret->value.rend());
		} else if (kdf == u"HASH" || kdf == u"HMAC") {
			const auto hash_name = parameters.contains(0) ? digest_name(parameter_name(parameter(0))) : std::string("SHA1");
			auto input = parameter(1);
			input.insert(input.end(), secret->value.begin(), secret->value.end());
			const auto append = parameter(2);
			input.insert(input.end(), append.begin(), append.end());
			if (kdf == u"HASH") {
				derived = digest(hash_name, input);
			} else {
				auto key = parameter(3);
				if (key.empty())
					key = secret->value;
				std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
				size_t length = 0;
				if (EVP_Q_mac(nullptr, "HMAC", nullptr, hash_name.c_str(), nullptr, key.data(), key.size(), input.data(), input.size(), out.data(),
					out.size(), &length))
					out.resize(length), derived = out;
			}
		} else {
			if (std::getenv("RAVEN_TRACE_FAIL"))
				std::fprintf(stderr, "raven: bcrypt key derivation %s is not supported\n", to_utf8(kdf).c_str());
			call.ret(status_not_supported);
			return;
		}
		if (derived.empty()) {
			call.ret(status_unsuccessful);
			return;
		}
		if (call[3] && call.u32(4) < derived.size() && kdf != u"TRUNCATE")
			derived.resize(call.u32(4));
		call.ret(answer(call, call[3], call.u32(4), call[5], derived));
	});

	// Signatures: RSA with the padding the call names, ECDSA as r and s of the curve's size each.
	registry.add("BCryptSignHash", 8, [rsa_padding](ApiCall &call) {
		auto key = table().get<Key>(call[0]);
		if (!key || !key->pair) {
			call.ret(status_invalid_handle);
			return;
		}
		const auto hash = call.read(call[2], call.u32(3));
		const bool ecdsa = key->algorithm->kind == Kind::ecdsa;
		const size_t field = ecdsa ? field_bytes(key_group(key->pair)) : 0;
		const size_t size = ecdsa ? 2 * field : size_t(EVP_PKEY_get_size(key->pair));
		if (!call[4]) {
			call.store<uint32_t>(call[6], uint32_t(size));
			call.ret(status_success);
			return;
		}
		if (call.u32(5) < size) {
			call.ret(status_buffer_too_small);
			return;
		}
		EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(nullptr, key->pair, nullptr);
		size_t length = 0;
		bool good = context && EVP_PKEY_sign_init(context) == 1 && (ecdsa || rsa_padding(call, context, call[1], call.u32(7), true)) &&
			EVP_PKEY_sign(context, nullptr, &length, hash.data(), hash.size()) == 1;
		std::vector<uint8_t> signature(length);
		good = good && EVP_PKEY_sign(context, signature.data(), &length, hash.data(), hash.size()) == 1;
		EVP_PKEY_CTX_free(context);
		if (!good) {
			call.ret(status_invalid_parameter);
			return;
		}
		signature.resize(length);
		if (ecdsa) {
			const uint8_t *at = signature.data();
			ECDSA_SIG *parsed = d2i_ECDSA_SIG(nullptr, &at, long(signature.size()));
			if (!parsed) {
				call.ret(status_unsuccessful);
				return;
			}
			auto r = big_endian(ECDSA_SIG_get0_r(parsed), field), s = big_endian(ECDSA_SIG_get0_s(parsed), field);
			ECDSA_SIG_free(parsed);
			signature = r;
			signature.insert(signature.end(), s.begin(), s.end());
		}
		call.write(call[4], signature);
		call.store<uint32_t>(call[6], uint32_t(signature.size()));
		call.ret(status_success);
	});
	registry.add("BCryptVerifySignature", 7, [rsa_padding](ApiCall &call) {
		auto key = table().get<Key>(call[0]);
		if (!key || !key->pair) {
			call.ret(status_invalid_handle);
			return;
		}
		const auto hash = call.read(call[2], call.u32(3));
		auto signature = call.read(call[4], call.u32(5));
		const bool ecdsa = key->algorithm->kind == Kind::ecdsa;
		if (ecdsa) {
			const size_t field = field_bytes(key_group(key->pair));
			if (signature.size() != 2 * field) {
				call.ret(status_invalid_signature);
				return;
			}
			ECDSA_SIG *parsed = ECDSA_SIG_new();
			ECDSA_SIG_set0(parsed, number(signature.data(), field), number(signature.data() + field, field));
			unsigned char *encoded = nullptr;
			const int length = i2d_ECDSA_SIG(parsed, &encoded);
			ECDSA_SIG_free(parsed);
			if (length <= 0) {
				call.ret(status_invalid_signature);
				return;
			}
			signature.assign(encoded, encoded + length);
			OPENSSL_free(encoded);
		}
		EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(nullptr, key->pair, nullptr);
		const bool good = context && EVP_PKEY_verify_init(context) == 1 && (ecdsa || rsa_padding(call, context, call[1], call.u32(6), true)) &&
			EVP_PKEY_verify(context, signature.data(), signature.size(), hash.data(), hash.size()) == 1;
		EVP_PKEY_CTX_free(context);
		call.ret(good ? status_success : status_invalid_signature);
	});

	// Random bytes from the system generator: its pseudo handle, a random number provider, or no handle with the preferred-generator flag.
	registry.add("BCryptGenRandom", 4, [](ApiCall &call) {
		auto algorithm = call[0] ? algorithm_of(call[0]) : nullptr;
		const bool generator = (algorithm && algorithm->kind == Kind::rng) || (!call[0] && (call.u32(3) & 2));
		if (!generator || (!call[1] && call.u32(2))) {
			call.ret(generator ? status_invalid_parameter : status_invalid_handle);
			return;
		}
		std::vector<uint8_t> bytes(call.u32(2));
		if (!bytes.empty() && RAND_bytes(bytes.data(), int(bytes.size())) != 1) {
			call.ret(status_unsuccessful);
			return;
		}
		call.write(call[1], bytes);
		call.ret(status_success);
	});

	// PBKDF2 over an HMAC provider, as programs derive keys from passwords.
	registry.add("BCryptDeriveKeyPBKDF2", 10, [](ApiCall &call) {
		auto algorithm = algorithm_of(call[0]);
		if (!algorithm || algorithm->kind != Kind::hash || !algorithm->hmac) {
			call.ret(algorithm ? status_invalid_parameter : status_invalid_handle);
			return;
		}
		const auto password = call[1] ? call.read(call[1], call.u32(2)) : std::vector<uint8_t>();
		const auto salt = call[3] ? call.read(call[3], call.u32(4)) : std::vector<uint8_t>();
		const uint64_t iterations = call.pointer_width() == 8 ? call[5] : (call[5] | uint64_t(call.u32(6)) << 32);
		const size_t shift = call.pointer_width() == 8 ? 0 : 1;
		const uint64_t output = call[6 + shift];
		const uint32_t size = call.u32(7 + shift);
		std::vector<uint8_t> derived(size);
		if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(password.data()), int(password.size()), salt.data(), int(salt.size()), int(iterations),
			EVP_get_digestbyname(algorithm->digest.c_str()), int(size), derived.data())) {
			call.ret(status_unsuccessful);
			return;
		}
		call.write(output, derived);
		call.ret(status_success);
	});
}

#else

void register_bcrypt_api(ApiRegistry &, KernelContext &)
{
}

#endif

}
