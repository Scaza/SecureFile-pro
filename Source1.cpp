#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/applink.c>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// RSA Key Manager Class
class RSAKeyManager {
public:
    void generateKeyPair(const std::string& publicKeyFile, const std::string& privateKeyFile) {
        RSA* rsa = RSA_new();
        BIGNUM* bne = BN_new();
        BN_set_word(bne, RSA_F4);

        if (RSA_generate_key_ex(rsa, 4096, bne, nullptr) != 1) {
            handleOpenSSLError();
        }

        // Save public key to file
        FILE* pubFile = fopen(publicKeyFile.c_str(), "wb");
        if (!pubFile) throw std::runtime_error("Error opening public key file for writing.");
        PEM_write_RSA_PUBKEY(pubFile, rsa); // Corrected function
        fclose(pubFile);

        // Save private key to file
        FILE* privFile = fopen(privateKeyFile.c_str(), "wb");
        if (!privFile) throw std::runtime_error("Error opening private key file for writing.");
        PEM_write_RSAPrivateKey(privFile, rsa, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(privFile);

        RSA_free(rsa);
        BN_free(bne);

        std::cout << "RSA Key pair generated and saved to files.\n";
    }

    std::vector<unsigned char> encryptAESKey(const std::vector<unsigned char>& aesKey, const std::string& publicKeyFile) {
        FILE* pubFp = fopen(publicKeyFile.c_str(), "rb");
        if (!pubFp) throw std::runtime_error("Error opening public key file for reading.");
        RSA* rsa = PEM_read_RSA_PUBKEY(pubFp, nullptr, nullptr, nullptr);
        fclose(pubFp);

        if (!rsa) throw std::runtime_error("Error reading public key.");

        std::vector<unsigned char> encryptedKey(RSA_size(rsa));
        int encryptedLen = RSA_public_encrypt(aesKey.size(), aesKey.data(), encryptedKey.data(), rsa, RSA_PKCS1_OAEP_PADDING);

        RSA_free(rsa);

        if (encryptedLen == -1) {
            handleOpenSSLError();
        }

        encryptedKey.resize(encryptedLen);
        return encryptedKey;
    }

    std::vector<unsigned char> decryptAESKey(const std::vector<unsigned char>& encryptedKey, const std::string& privateKeyFile) {
        FILE* privFp = fopen(privateKeyFile.c_str(), "rb");
        if (!privFp) throw std::runtime_error("Error opening private key file for reading.");
        RSA* rsa = PEM_read_RSAPrivateKey(privFp, nullptr, nullptr, nullptr);
        fclose(privFp);

        if (!rsa) throw std::runtime_error("Error reading private key.");

        std::vector<unsigned char> decryptedKey(RSA_size(rsa));
        int decryptedLen = RSA_private_decrypt(encryptedKey.size(), encryptedKey.data(), decryptedKey.data(), rsa, RSA_PKCS1_OAEP_PADDING);

        RSA_free(rsa);

        if (decryptedLen == -1) {
            handleOpenSSLError();
        }

        decryptedKey.resize(decryptedLen);
        return decryptedKey;
    }

private:
    void handleOpenSSLError() {
        char errBuffer[120];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), errBuffer);
        throw std::runtime_error(std::string("OpenSSL error: ") + errBuffer);
    }
};

// File Encryptor Class
class FileEncryptor {
private:
    std::string inputFilePath;
    std::string outputFilePath;
    std::vector<unsigned char> aesKey;

public:
    FileEncryptor(const std::string& inPath, const std::string& outPath)
        : inputFilePath(inPath), outputFilePath(outPath) {
    }

    void setKey(const std::vector<unsigned char>& key) {
        if (key.size() != 32) {
            throw std::runtime_error("AES key must be 256 bits (32 bytes).");
        }
        aesKey = key;
    }

    void encryptFile();
    void decryptFile();
};

void FileEncryptor::encryptFile() {
    const int ivLength = 12;
    const int tagLength = 16;
    unsigned char iv[ivLength];
    unsigned char tag[tagLength];

    RAND_bytes(iv, ivLength);

    std::ifstream infile(inputFilePath, std::ios::binary);
    std::ofstream outfile(outputFilePath, std::ios::binary);
    if (!infile || !outfile) throw std::runtime_error("File error during encryption.");

    std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
    std::vector<unsigned char> ciphertext(plaintext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, aesKey.data(), iv);

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tagLength, tag);
    EVP_CIPHER_CTX_free(ctx);

    outfile.write((char*)iv, ivLength);
    outfile.write((char*)ciphertext.data(), ciphertext_len);
    outfile.write((char*)tag, tagLength);
}

void FileEncryptor::decryptFile() {
    const int ivLength = 12;
    const int tagLength = 16;

    std::ifstream infile(inputFilePath, std::ios::binary);
    std::ofstream outfile(outputFilePath, std::ios::binary);
    if (!infile || !outfile) throw std::runtime_error("File error during decryption.");

    infile.seekg(0, std::ios::end);
    size_t totalSize = infile.tellg();
    infile.seekg(0, std::ios::beg);

    std::vector<unsigned char> iv(ivLength);
    infile.read((char*)iv.data(), ivLength);

    size_t ciphertextSize = totalSize - ivLength - tagLength;
    std::vector<unsigned char> ciphertext(ciphertextSize);
    infile.read((char*)ciphertext.data(), ciphertextSize);

    std::vector<unsigned char> tag(tagLength);
    infile.read((char*)tag.data(), tagLength);

    std::vector<unsigned char> plaintext(ciphertextSize);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, aesKey.data(), iv.data());

    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLength, tag.data());

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: authentication error.");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    outfile.write((char*)plaintext.data(), plaintext_len);
}

int main() {
    try {
        RSAKeyManager keyManager;
        keyManager.generateKeyPair("public.pem", "private.pem");

        std::vector<unsigned char> aesKey(32);
        RAND_bytes(aesKey.data(), 32);

        std::vector<unsigned char> encryptedAESKey = keyManager.encryptAESKey(aesKey, "public.pem");

        std::string originalFile = "plain.txt";
        std::string encryptedFile = "encrypted.bin";
        std::string decryptedFile = "decrypted.txt";

        std::ofstream plainOut(originalFile);
        plainOut << "This is a test file for AES-256-GCM encryption.";
        plainOut.close();

        FileEncryptor encryptor(originalFile, encryptedFile);
        encryptor.setKey(aesKey);
        encryptor.encryptFile();
        std::cout << "File encryption successful.\n";

        std::vector<unsigned char> decryptedAESKey = keyManager.decryptAESKey(encryptedAESKey, "private.pem");

        FileEncryptor decryptor(encryptedFile, decryptedFile);
        decryptor.setKey(decryptedAESKey);
        decryptor.decryptFile();
        std::cout << "File decryption successful.\n";

    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }

    return 0;
}