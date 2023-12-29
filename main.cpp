#include <stdio.h>
#include <sodium.h>
#include <iostream>
#include <string.h>
#include <fstream>

#define CHUNK_SIZE 4096

using std::cin;
using std::cout;
using std::endl;
using std::string;

static int
encrypt(const char *target_file, const char *source_file,
        const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char buf_in[CHUNK_SIZE];
    unsigned char buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *fp_t, *fp_s;
    unsigned long long out_len;
    size_t rlen;
    int eof;
    unsigned char tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);
    do
    {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
                                                   NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    fclose(fp_t);
    fclose(fp_s);
    return 0;
}

static int
decrypt(const char *target_file, const char *source_file,
        const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char buf_out[CHUNK_SIZE];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *fp_t, *fp_s;
    unsigned long long out_len;
    size_t rlen;
    int eof;
    int ret = -1;
    unsigned char tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0)
    {
        goto ret; /* incomplete header */
    }
    do
    {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                                                       buf_in, rlen, NULL, 0) != 0)
        {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        {
            if (!eof)
            {
                goto ret; /* end of stream reached before the end of the file */
            }
        }
        else
        { /* not the final chunk yet */
            if (eof)
            {
                goto ret; /* end of file reached before the end of the stream */
            }
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

string password_form_user()
{
    return "password";
}

void hash_password(unsigned char (&key)[crypto_secretstream_xchacha20poly1305_KEYBYTES], string password)
{
    // Initialize the Sodium library
    if (sodium_init() < 0)
    {
        std::cerr << "Error initializing Sodium library" << std::endl;
        exit(1);
    }

    // Generate a random salt
    std::string salt(crypto_pwhash_SALTBYTES, '\0');
    randombytes_buf(reinterpret_cast<unsigned char *>(&salt[0]), salt.size());

    // Hash the password using the Argon2id algorithm
    std::string hash(crypto_pwhash_STRBYTES, '\0');
    if (crypto_pwhash_str(
            &hash[0],
            password.c_str(),
            password.length(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
        std::cerr << "Error hashing password" << std::endl;
        exit(1);
    }

    for (int i = 0; i < 32; i++)
    {
        key[i] = static_cast<unsigned char>(hash[i]);
    }
}

int main(void)
{
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    if (sodium_init() != 0)
    {
        return 1;
    }

    string password = password_form_user();

    hash_password(key, password);

    std::string password = "mysecretpassword";
    std::string hashedPassword = key;

    cout << key << endl;

    // if (encrypt("./tmp/encrypted", "./tmp/original", key) != 0)
    // {
    //     std::cout << "encrypt" << std::endl;
    //     return 1;
    // }

    if (decrypt("./tmp/decrypted", "./tmp/encrypted", key) != 0)
    {
        std::cout << "decrypt" << std::endl;
        return 1;
    }

    return 0;
}