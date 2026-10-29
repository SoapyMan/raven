#include <windows.h>
#include <wincrypt.h>

/* CryptoAPI session keys: an AES-128 key imported as a PLAINTEXTKEYBLOB encrypts the first block of the CBC vector of NIST SP 800-38A
   (F.2.1) from its IV; a generated AES-256 key pads a final message to the next block, decrypts it back and exports as the length a
   PLAINTEXTKEYBLOB of it needs. */

static const BYTE key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const BYTE iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const BYTE plain[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
static const BYTE cipher[16] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d};

static int same(const BYTE *left, const BYTE *right, DWORD length)
{
	for (DWORD at = 0; at < length; ++at)
		if (left[at] != right[at])
			return 0;
	return 1;
}

static int known_vector(HCRYPTPROV provider)
{
	struct {
		BLOBHEADER header;
		DWORD length;
		BYTE secret[16];
	} blob = {{PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, CALG_AES_128}, 16, {0}};
	HCRYPTKEY session;
	BYTE data[32];
	DWORD length = 16, value = 0, size = sizeof(value);
	for (int at = 0; at < 16; ++at)
		blob.secret[at] = key[at];
	if (!CryptImportKey(provider, (BYTE *)&blob, sizeof(blob), 0, 0, &session))
		return 1;
	if (!CryptGetKeyParam(session, KP_KEYLEN, (BYTE *)&value, &size, 0) || value != 128)
		return 2;
	if (!CryptSetKeyParam(session, KP_IV, (BYTE *)iv, 0))
		return 3;
	for (int at = 0; at < 16; ++at)
		data[at] = plain[at];
	if (!CryptEncrypt(session, 0, FALSE, 0, data, &length, sizeof(data)) || length != 16 || !same(data, cipher, 16))
		return 4;
	CryptDestroyKey(session);
	return 0;
}

static int round_trip(HCRYPTPROV provider)
{
	static const char message[] = "nineteen characters";
	HCRYPTKEY session;
	BYTE data[48], exported[64];
	DWORD length = sizeof(message) - 1, needed = length, size = sizeof(exported);
	if (!CryptGenKey(provider, CALG_AES_256, CRYPT_EXPORTABLE, &session))
		return 10;
	if (!CryptEncrypt(session, 0, TRUE, 0, NULL, &needed, 0) || needed != 32)
		return 11;
	for (DWORD at = 0; at < length; ++at)
		data[at] = (BYTE)message[at];
	if (CryptEncrypt(session, 0, TRUE, 0, data, &length, 16) || GetLastError() != ERROR_MORE_DATA || length != 32)
		return 12;
	length = sizeof(message) - 1;
	if (!CryptEncrypt(session, 0, TRUE, 0, data, &length, sizeof(data)) || length != 32)
		return 13;
	if (!CryptDecrypt(session, 0, TRUE, 0, data, &length) || length != sizeof(message) - 1 || !same(data, (const BYTE *)message, length))
		return 14;
	if (!CryptExportKey(session, 0, PLAINTEXTKEYBLOB, 0, exported, &size) || size != 12 + 32 || exported[0] != PLAINTEXTKEYBLOB)
		return 15;
	CryptDestroyKey(session);
	return 0;
}

int raven_entry(void)
{
	HCRYPTPROV provider;
	if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		return 20;
	int result = known_vector(provider);
	if (!result)
		result = round_trip(provider);
	CryptReleaseContext(provider, 0);
	return result;
}
