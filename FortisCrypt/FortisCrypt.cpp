#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

class FileEncryptor {
private:
    std::string inputFilePath;
    std::string outputFilePath;
    std::vector<unsigned char> aesKey; // 256-bit key (32 bytes)

public:
    FileEncryptor(const std::string& inPath, const std::string& outPath)
        : inputFilePath(inPath), outputFilePath(outPath) {}

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
    const int ivLength = 12; // Recommended IV length for GCM
    const int tagLength = 16;
    unsigned char iv[ivLength];
    unsigned char tag[tagLength];

    RAND_bytes(iv, ivLength); // Generate random IV

    std::ifstream infile(inputFilePath, std::ios::binary);
    std::ofstream outfile(outputFilePath, std::ios::binary);
    if (!infile || !outfile) throw std::runtime_error("File error during encryption.");

    std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(infile)),
        std::istreambuf_iterator<char>());

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

    // Write IV + ciphertext + tag to output file
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
        // Generate random 256-bit AES key
        std::vector<unsigned char> aesKey(32);
        RAND_bytes(aesKey.data(), 32);

        // Set file paths
        std::string originalFile = "plain.txt";
        std::string encryptedFile = "encrypted.bin";
        std::string decryptedFile = "decrypted.txt";

        // Create dummy plain file
        std::ofstream plainOut(originalFile);
        plainOut << "This is a test file for AES-256-GCM encryption.";
        plainOut.close();

        FileEncryptor encryptor(originalFile, encryptedFile);
        encryptor.setKey(aesKey);
        encryptor.encryptFile();
        std::cout << "Encryption successful.\n";

        FileEncryptor decryptor(encryptedFile, decryptedFile);
        decryptor.setKey(aesKey);
        decryptor.decryptFile();
        std::cout << "Decryption successful.\n";

    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }

    return 0;
}