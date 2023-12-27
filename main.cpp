#include <iostream>
#include <fstream>
#include <string.h>
#include <sodium.h>
#include <stdint.h>
#include <memory>
#include <vector>
#include <stdio.h>

using std::string;
#define CHUNK_SIZE 4096

class Error
{
public:
    static void BigExit(int i)
    {
        std::cout << "Error " << i << std::endl;
        exit(i);
    }

    static void print(string s)
    {
        std::cout << "print : " << s << std::endl;
    }
};

class Encripsion
{
private:
public:
    static unsigned char *p_key;
    void hash_string(string &s)
    {
        // https://doc.libsodium.org/password_hashing/default_phf

        unsigned char salt[crypto_pwhash_SALTBYTES];
        unsigned char key[crypto_box_SEEDBYTES];
        char hashed_password[crypto_pwhash_STRBYTES];
        const char *inputPassword = s.c_str();

        randombytes_buf(salt, sizeof salt);

        if (crypto_pwhash(
                key,
                sizeof key,
                inputPassword,
                strlen(inputPassword),
                salt,
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                crypto_pwhash_ALG_DEFAULT) != 0)
        {

            /* out of memory */
            Error::BigExit(3);
        }

        p_key = key;

        if (crypto_pwhash_str(hashed_password, inputPassword, strlen(inputPassword),
                              crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0)
        {
        }

        if (PasswordCheck(hashed_password, inputPassword))
        {
            Error::BigExit(4);
        }
    }

    bool PasswordCheck(char hashed_password[128], const char *s)
    {
        if (crypto_pwhash_str_verify(hashed_password, s, strlen(s)) != 0)
        {
            /* wrong password */
            std::clog << "wrong password or wrong file:" << std::endl;
            return true;
        }
        std::clog << "good password:" << std::endl;
        return false;
    }

    static int hash_file_metod(const char *target_file, const char *source_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
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
    };

    static int unhash_file_metod(const char *target_file, const char *source_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
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

    static void hash_file(unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], string path)
    {

        string decrypted = "/tmp/decrypted";
        string encrypted = path;

        if (hash_file_metod(encrypted.c_str(), decrypted.c_str(), key) != 0)
        {
            std::clog << "Error hash_file_metod" << std::endl;
        }
    }

    static void unhash_file(unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], string path)
    {
        string decrypted = "/tmp/decrypted";
        string encrypted = path;

        if (unhash_file_metod(decrypted.c_str(), encrypted.c_str(), key) != 0)
        {
            std::clog << "Error unhash_file_metod" << std::endl;
        }
    }
};

class FileHandle
{

private:
    void checkIfItsMyFile(string str)
    {
        std::ifstream ifile;
        ifile.open(str);

        if (!ifile.is_open())
        {

            std::cout << "File not found" << std::endl;

            char ats;

            std::cout << "Do you want to craite a new password DataBase? Y/N" << std::endl;

            std::cin >> ats;

            if (tolower(ats) == 'n')
            {
                exit(0);
            }

            std::ofstream ofile(str);

            string password;
            std::cout << "new Password for file" << std::endl;
            std::cin >> password;

            Encripsion encripsion;
            string passwordString = password.data();

            encripsion.hash_string(passwordString);

            ofile << passwordString << std::endl;

            hashed_password_from_user = passwordString;

            std::cout << std::endl;

            ofile.close();
            // TODO Save the password to the file;
        }

        std::getline(ifile, hashed_password_from_file);
    }

    void inputCheck(string file)
    {
        std::ifstream ifile;
        ifile.open(file);

        string s;

        std::getline(ifile, s);
    }

public:
    static string hashed_password_from_file;
    static string hashed_password_from_user;

    static string pathOfPassFile;
    static string password;
    void check_user_file_password()
    {
        Encripsion encripsion;
        encripsion.PasswordCheck(hashed_password_from_file.data(), password.data());
    }

    void open_password_file()
    {
        std::cout << "Opening a file" << std::endl;
        checkIfItsMyFile(pathOfPassFile);
    }

    void take_password_from_user()
    {
        inputCheck(pathOfPassFile);

        std::cout << "Hello" << std::endl
                  << "Please previde a password for the file: " << std::endl;

        std::cin >> password;
    }

    FileHandle(string path)
    {
        pathOfPassFile = path;
    }
};

class InDataBase
{
private:
    struct Passwords
    {
        int id;
        string name;
        string userName;
        string password;
    };

public:
    void print_all_words()
    {
        std::ifstream ifile;

        ifile.open(FileHandle::pathOfPassFile);
        ifile.ignore(99);

        int id;
        string username, name, password;
        std::vector<Passwords> password_vector;

        int size = 0;

        while (ifile >> id >> username >> name >> password)
        {
            size++;

            password_vector.resize(size);
            password_vector[size - 1].id = id;

            std::cout << id << "\t" << username << "\t" << name << "\t" << password << std::endl;
        }
    }
};

string FileHandle::password;
string FileHandle::pathOfPassFile;
string FileHandle::hashed_password_from_file;
string FileHandle::hashed_password_from_user;
unsigned char *Encripsion::p_key;

int main(int argc, char const *argv[])
{
    FileHandle fileHandle(argv[1]);
    Encripsion encripsion;
    unsigned char key[crypto_box_SEEDBYTES] = "pass";

    if (sodium_init() < 0)
    {
        Error::BigExit(2);
    }

    if (argc != 2)
    {
        Error::BigExit(1);
    }
    encripsion.hash_file(key, fileHandle.pathOfPassFile);
    encripsion.unhash_file(key, fileHandle.pathOfPassFile);

    fileHandle.open_password_file();

    fileHandle.take_password_from_user();

    fileHandle.check_user_file_password();

    InDataBase inDataBase;

    inDataBase.print_all_words();

    // ToDo Some how get a key form the password

    encripsion.hash_file(key, fileHandle.pathOfPassFile);

    // TODO The hash password can be used as a seed for the oder passwords. The last n digets are the seed for the incripsion. Anyone can't read the password widaut the main password hash

    // TODO whate for the user to diside what to do, does he want to get a pasword or does he wnat to add new one, or edit, or removie

    std::cout << "Done"
              << "\n";
    return 0;
}
