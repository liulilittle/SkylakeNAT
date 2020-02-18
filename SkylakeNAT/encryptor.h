#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <string>
#include <memory>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "env.h"
#include "monitor.h"

static const char* ENCRYPTOR_AES_256_CFB = "aes-256-cfb";
static const char* ENCRYPTOR_AES_192_CFB = "aes-192-cfb";
static const char* ENCRYPTOR_AES_128_CFB = "aes-128-cfb";

class Encryptor : public std::enable_shared_from_this<Encryptor>
{
public:
	explicit Encryptor(const Encryptor&) = default;
	Encryptor(const std::string method, const std::string password);
	virtual ~Encryptor();

public:
	static void											Initialize();

public:
	virtual void										Dispose();
	virtual std::shared_ptr<unsigned char>				Encrypt(unsigned char* data, int datalen, int& outlen);
	virtual std::shared_ptr<unsigned char>				Decrypt(unsigned char* data, int datalen, int& outlen);

protected:
	virtual std::shared_ptr<unsigned char>				New(int length, int memset = ~0);

private:
	void												initCipher(std::shared_ptr<EVP_CIPHER_CTX>& context, 
		const unsigned char* iv, int ivlen, bool isCipher);
	void												initKey(const std::string& method, const std::string password);

private:
	const EVP_CIPHER*									_cipher;
	std::shared_ptr<EVP_CIPHER_CTX>						_context;
	std::shared_ptr<unsigned char>						_key; // _cipher->key_len
	std::shared_ptr<unsigned char>						_iv;
	std::string											_method;
	std::string											_password;
	std::shared_ptr<EVP_CIPHER_CTX>						_encryptCTX;
	std::shared_ptr<EVP_CIPHER_CTX>						_decryptCTX;
	Monitor												_syncobj;
};