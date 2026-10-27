#include <windows.h>
#include <bcrypt.h>

/* Names of the Windows 10 SDK that older MinGW headers lack. */
#ifndef BCRYPT_ECDH_ALGORITHM
#define BCRYPT_ECDH_ALGORITHM L"ECDH"
#endif
#ifndef BCRYPT_ECC_CURVE_NAME
#define BCRYPT_ECC_CURVE_NAME L"ECCCurveName"
#endif
#ifndef BCRYPT_ECC_CURVE_SECP256K1
#define BCRYPT_ECC_CURVE_SECP256K1 L"secP256k1"
#endif

/* AES-GMAC as SSH clients probe and use it: a MAC keyed at creation whose nonce is the hash's IV, checked against the published
   GCM vectors with an empty plaintext; a reusable hash started over with a new nonce; and an ECDH key on secp256k1, exported with the
   generic magic of curves chosen by name. */

static const UCHAR zero_tag[16] = {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
static const UCHAR key[16] = {0x77, 0xbe, 0x63, 0x70, 0x89, 0x71, 0xc4, 0xe2, 0x40, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x7f, 0xeb};
static const UCHAR nonce[12] = {0xe0, 0xe0, 0x0f, 0x19, 0xfe, 0xd7, 0xba, 0x01, 0x36, 0xa7, 0x97, 0xf3};
static const UCHAR data[16] = {0x7a, 0x43, 0xec, 0x1d, 0x9c, 0x0a, 0x5a, 0x78, 0xa0, 0xb1, 0x65, 0x33, 0xa6, 0x21, 0x3c, 0xab};
static const UCHAR tag[16] = {0x20, 0x9f, 0xcc, 0x8d, 0x36, 0x75, 0xed, 0x93, 0x8e, 0x9c, 0x71, 0x66, 0x70, 0x9d, 0xd9, 0x46};

static BOOL same(const UCHAR *a, const UCHAR *b, ULONG size)
{
	while (size--)
		if (a[size] != b[size])
			return FALSE;
	return TRUE;
}

static int gmac(void)
{
	BCRYPT_ALG_HANDLE algorithm;
	BCRYPT_HASH_HANDLE hash;
	UCHAR zero_key[16] = {0}, zero_nonce[12] = {0}, out[16];
	DWORD length = 0, written = 0;

	if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_GMAC_ALGORITHM, NULL, 0))
		return 1;
	if (BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, (UCHAR *)&length, sizeof(length), &written, 0) || length != 16)
		return 2;
	if (BCryptCreateHash(algorithm, &hash, NULL, 0, zero_key, sizeof(zero_key), BCRYPT_HASH_REUSABLE_FLAG))
		return 3;
	if (BCryptSetProperty(hash, BCRYPT_INITIALIZATION_VECTOR, zero_nonce, sizeof(zero_nonce), 0) || BCryptFinishHash(hash, out, 16, 0) ||
		!same(out, zero_tag, 16))
		return 4;
	BCryptDestroyHash(hash);
	if (BCryptCreateHash(algorithm, &hash, NULL, 0, (UCHAR *)key, sizeof(key), BCRYPT_HASH_REUSABLE_FLAG))
		return 5;
	if (BCryptSetProperty(hash, BCRYPT_INITIALIZATION_VECTOR, (UCHAR *)nonce, sizeof(nonce), 0) ||
		BCryptHashData(hash, (UCHAR *)data, sizeof(data), 0) || BCryptFinishHash(hash, out, 16, 0) || !same(out, tag, 16))
		return 6;
	/* The same hash again, its nonce set anew. */
	if (BCryptSetProperty(hash, BCRYPT_INITIALIZATION_VECTOR, (UCHAR *)nonce, sizeof(nonce), 0) ||
		BCryptHashData(hash, (UCHAR *)data, 8, 0) || BCryptHashData(hash, (UCHAR *)data + 8, 8, 0) || BCryptFinishHash(hash, out, 16, 0) ||
		!same(out, tag, 16))
		return 7;
	BCryptDestroyHash(hash);
	BCryptCloseAlgorithmProvider(algorithm, 0);
	return 0;
}

static int secp256k1(void)
{
	BCRYPT_ALG_HANDLE algorithm;
	BCRYPT_KEY_HANDLE pair;
	UCHAR blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
	ULONG written = 0;
	const BCRYPT_ECCKEY_BLOB *header = (const BCRYPT_ECCKEY_BLOB *)blob;

	if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDH_ALGORITHM, NULL, 0))
		return 10;
	if (BCryptSetProperty(algorithm, BCRYPT_ECC_CURVE_NAME, (UCHAR *)BCRYPT_ECC_CURVE_SECP256K1,
		sizeof(BCRYPT_ECC_CURVE_SECP256K1), 0))
		return 11;
	if (BCryptGenerateKeyPair(algorithm, &pair, 0, 0) || BCryptFinalizeKeyPair(pair, 0))
		return 12;
	if (BCryptExportKey(pair, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &written, 0) || written != sizeof(blob) ||
		header->dwMagic != BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC || header->cbKey != 32)
		return 13;
	BCryptDestroyKey(pair);
	BCryptCloseAlgorithmProvider(algorithm, 0);
	return 0;
}

static volatile LONG hashing_failed;

/* Hashes made and destroyed in a loop while other threads take and give back blocks of the process heap the handles also come from. */
static DWORD WINAPI hash_loop(void *unused)
{
	for (int round = 0; round < 300; ++round) {
		BCRYPT_HASH_HANDLE hash = NULL;
		UCHAR digest[32];
		if (BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hash, NULL, 0, NULL, 0, 0) || BCryptHashData(hash, (UCHAR *)data, sizeof data, 0) ||
			BCryptFinishHash(hash, digest, sizeof digest, 0) || BCryptDestroyHash(hash))
			InterlockedExchange(&hashing_failed, 1);
	}
	return 0;
}

static DWORD WINAPI heap_loop(void *unused)
{
	for (int round = 0; round < 3000; ++round)
		HeapFree(GetProcessHeap(), 0, HeapAlloc(GetProcessHeap(), 0, 16 + round % 512));
	return 0;
}

static int concurrent_hashes(void)
{
	HANDLE threads[6];
	for (int index = 0; index < 6; ++index)
		if (!(threads[index] = CreateThread(NULL, 0, index % 2 ? heap_loop : hash_loop, NULL, 0, NULL))) return 30;
	if (WaitForMultipleObjects(6, threads, TRUE, 15000) != WAIT_OBJECT_0) return 31;
	return hashing_failed ? 32 : 0;
}

int raven_entry(void)
{
	int result = gmac();
	if (!result) result = secp256k1();
	return result ? result : concurrent_hashes();
}
