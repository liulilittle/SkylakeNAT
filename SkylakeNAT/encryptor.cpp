#include "env.h"
#include "rc4.h"
#include "md5.h"
#include "encryptor.h"
#include "nedmalloc/memory.h"

#include <string>
#include <sstream>
#include <iostream>

Encryptor::Encryptor(const std::string method, const std::string password)
	: _cipher(NULL)
	, _method(method)
	, _password(password)
{
	initKey(method, password);
	initIV(method, password);
}

Encryptor::~Encryptor()
{
	Dispose();
}

void Encryptor::Initialize()
{
	/* initialize OpenSSL */
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();
	ERR_load_EVP_strings();
	ERR_load_crypto_strings();
}

void Encryptor::Dispose()
{
	_cipher = NULL;
	_context = NULL;
	_key = NULL;
	_encryptCTX = NULL;
	_decryptCTX = NULL;
}

std::shared_ptr<unsigned char> Encryptor::Encrypt(unsigned char* data, int datalen, int& outlen)
{
	outlen = 0;
	if (datalen < 0 || (!data && datalen)) {
		outlen = ~0;
		return NULL;
	}

	if (datalen == 0) {
		return NULL;
	}

	MonitorScope scope(_syncobj);
	// ENCR-DATA
	int outLen = datalen + _cipher->block_size;
	std::shared_ptr<unsigned char> cipherText = New(outLen);
	if (EVP_CipherUpdate(_encryptCTX.get(), cipherText.get(), &outLen, data, datalen) <= 0)
	{
		outlen = ~0;
		return NULL;
	}

	outlen = outLen;
	if (cipherText.get()) {
		cipherText.get()[outLen] = '\x0';
	}
	return cipherText;
}

std::shared_ptr<unsigned char> Encryptor::Decrypt(unsigned char* data, int datalen, int& outlen)
{
	outlen = 0;
	if (datalen < 0 || (!data && datalen)) {
		outlen = ~0;
		return NULL;
	}

	if (datalen == 0) {
		return NULL;
	}

	MonitorScope scope(_syncobj);
	// DECR-DATA
	int outLen = datalen + _cipher->block_size;
	std::shared_ptr<unsigned char> cipherText = New(outLen);
	if (EVP_CipherUpdate(_decryptCTX.get(), cipherText.get(), &outLen, data, datalen) <= 0) {
		outlen = ~0;
		return NULL;
	}

	outlen = outLen;
	if (cipherText.get()) {
		cipherText.get()[outLen] = '\x0';
	}
	return cipherText;
}

std::shared_ptr<unsigned char> Encryptor::New(int length, int memset)
{
	if (length <= 0)
		return NULL;
	unsigned char* bytes = (unsigned char*)Memory::Alloc((uint32_t)length);
	if (memset >= 0)
		::memset(bytes, 0, _cipher->iv_len);
	return std::shared_ptr<unsigned char>(bytes, [](unsigned char* p) {
		if (p)
			Memory::Free(p);
	});
}

std::shared_ptr<EVP_CIPHER_CTX> Encryptor::initCipher(const unsigned char* iv, int ivlen, bool isCipher)
{
	std::shared_ptr<EVP_CIPHER_CTX> context = std::shared_ptr<EVP_CIPHER_CTX>(
		(EVP_CIPHER_CTX*)OPENSSL_malloc(sizeof(EVP_CIPHER_CTX)), [](EVP_CIPHER_CTX* context)
	{
		if (context) {
			EVP_CIPHER_CTX_cleanup(context);
			OPENSSL_free(context);
		}
	});
	bool exception = false;
	do
	{
		int enc = isCipher ? 1 : 0;
		EVP_CIPHER_CTX_init(context.get());
		if (exception = EVP_CipherInit_ex(context.get(), _cipher, NULL, NULL, NULL, enc) <= 0)
			break;
		if (exception = EVP_CIPHER_CTX_set_key_length(context.get(), _cipher->key_len) <= 0)
			break;
		if (exception = EVP_CIPHER_CTX_set_padding(context.get(), 1) <= 0)
			break;
		if (exception = EVP_CipherInit_ex(context.get(), _cipher, NULL, _key.get(), iv, enc) <= 0)
			break;
	} while (0);
	if (exception) {
		context = NULL;
		throw std::runtime_error("There was a problem initializing the cipher that caused an exception to be thrown");
	}
	return context;
}

void Encryptor::initKey(const std::string& method, const std::string password)
{
	const char* cipherName = method.empty() ? ENCRYPTOR_AES_128_CFB : method.data();
	_cipher = EVP_get_cipherbyname(cipherName);
	if (!_cipher)
		throw std::runtime_error("Such encryption cipher methods are not supported");
	std::shared_ptr<unsigned char> iv = New(_cipher->iv_len, 0);

	_key = New(_cipher->key_len, 0);
	if (EVP_BytesToKey(_cipher, EVP_md5(), NULL, (unsigned char*)password.data(), (int)password.length(), 
		1, _key.get(), iv.get()) <= 0) {
		iv = NULL;
		throw std::runtime_error("Bytes to key calculations cannot be performed using cipher with md5(md) key password iv key etc");
	}
}

void Encryptor::initIV(const std::string& method, const std::string password)
{
	// INIT-IVV
	int ivLen = _cipher->iv_len;
	int md5len = ivLen < sizeof(MD5::HEX) ? sizeof(MD5::HEX) : ivLen;
	std::shared_ptr<unsigned char> iv = New(ivLen, 0); // RAND_bytes(iv.get(), ivLen);

	// MD5->RC4
	std::stringstream ss;
	ss << "SkylakeNAT@";
	ss << method;
	ss << ".";
	ss << std::string((char*)_key.get(), _cipher->key_len);
	ss << ".";
	ss << password;
	ComputeMD5(ss.str(), iv.get(), md5len);
	rc4_crypt(_key.get(), _cipher->key_len, iv.get(), ivLen, 0, 0);

	// INIT-CTX
	_encryptCTX = initCipher(iv.get(), ivLen, true);
	_decryptCTX = initCipher(iv.get(), ivLen, false);
}
