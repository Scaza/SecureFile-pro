#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

bool generateAESKey(std::vector<unsigned char>& key, std::vector<unsigned char>& iv) {
    key.resize(32); // AES-256
    iv.resize(12);  // GCM standard
    return RAND_bytes(key.data(), key.size()) && RAND_bytes(iv.data(), iv.size());
}

std::vector<unsigned char> rsaEncryptKey(const std::vector<unsigned char>& key, const std::string& public_key_file) {
    FILE* pubKeyFile = fopen(public_key_file.c_str(), "r");
    if (!pubKeyFile) handleErrors();

    EVP_PKEY* pubKey = PEM_read_PUBKEY(pubKeyFile, nullptr, nullptr, nullptr);
    fclose(pubKeyFile);
    if (!pubKey) handleErrors();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubKey, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, key.data(), key.size()) <= 0)
        handleErrors();

    std::vector<unsigned char> encrypted_key(outlen);
    if (EVP_PKEY_encrypt(ctx, encrypted_key.data(), &outlen, key.data(), key.size()) <= 0)
        handleErrors();

    encrypted_key.resize(outlen);
    EVP_PKEY_free(pubKey);
    EVP_PKEY_CTX_free(ctx);
    return encrypted_key;
}

std::vector<unsigned char> aesGCMEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        handleErrors();

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        handleErrors();

    std::vector<unsigned char> ciphertext(plaintext.size());
    int len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
        handleErrors();

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        handleErrors();
    ciphertext_len += len;

    tag.resize(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<unsigned char> rsaDecryptKey(const std::vector<unsigned char>& encrypted_key, const std::string& private_key_file) {
    FILE* privKeyFile = fopen(private_key_file.c_str(), "r");
    if (!privKeyFile) handleErrors();

    EVP_PKEY* privKey = PEM_read_PrivateKey(privKeyFile, nullptr, nullptr, nullptr);
    fclose(privKeyFile);
    if (!privKey) handleErrors();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, encrypted_key.data(), encrypted_key.size()) <= 0)
        handleErrors();

    std::vector<unsigned char> decrypted_key(outlen);
    if (EVP_PKEY_decrypt(ctx, decrypted_key.data(), &outlen, encrypted_key.data(), encrypted_key.size()) <= 0)
        handleErrors();

    decrypted_key.resize(outlen);
    EVP_PKEY_free(privKey);
    EVP_PKEY_CTX_free(ctx);
    return decrypted_key;
}

std::vector<unsigned char> aesGCMDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        handleErrors();

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        handleErrors();

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
        handleErrors();

    int plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data());

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return plaintext;
    }
    else {
        std::cerr << "Decryption failed: authentication tag mismatch." << std::endl;
        return {};
    }
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::vector<unsigned char> aes_key, iv;
    if (!generateAESKey(aes_key, iv)) handleErrors();

    std::vector<unsigned char> tag;
    std::string message = "Confidential file data.";
    std::vector<unsigned char> plaintext(message.begin(), message.end());

    auto ciphertext = aesGCMEncrypt(plaintext, aes_key, iv, tag);
    auto encrypted_key = rsaEncryptKey(aes_key, "public.pem");

    auto decrypted_key = rsaDecryptKey(encrypted_key, "private.pem");
    auto decrypted_text = aesGCMDecrypt(ciphertext, decrypted_key, iv, tag);

    std::string result(decrypted_text.begin(), decrypted_text.end());
    std::cout << "Decrypted text: " << result << std::endl;

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return 0;
}
