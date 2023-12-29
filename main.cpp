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
        exit(0);
    }

    static void print(string s)
    {
        std::cout << "print : " << s << std::endl;
    }
};

class Encripsion
{
private:
    static string old_locasion;

public:
    static unsigned char *p_key;
    static void hash_string(string &s)
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

        s = hashed_password;
    }

    static bool PasswordCheck(char hashed_password[128], const char *s)
    {
        if (crypto_pwhash_str_verify(hashed_password, s, strlen(s)) != 0)
        {
            /* wrong password */
            std::clog << "wrong password or wrong file:" << std::endl;
            return true;
        }
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

    static void hash_file(string key_string)
    {

        string decrypted = "/tmp/decrypted.md";
        string encrypted = old_locasion;

        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

        std::copy(key_string.begin(), key_string.end(), key);

        if (hash_file_metod(encrypted.c_str(), decrypted.c_str(), key) != 0)
        {
            std::clog << "Error hash_file_metod" << std::endl;
        }
    }

    static void unhash_file(string keyString, string &path)
    {
        string decrypted = "/tmp/decrypted.md";
        string encrypted = path;

        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

        std::copy(keyString.begin(), keyString.end(), key);

        std::clog << "key1 " << key << std::endl;

        if (unhash_file_metod(decrypted.c_str(), encrypted.c_str(), key) != 0)
        {
            std::clog << "Error unhash_file_metod" << std::endl;
        }

        std::clog << "key2 " << key << std::endl;

        old_locasion = path;
        path = decrypted;
    }

    static void gen_file(string _key, string &path)
    {
        string decrypted = "/tmp/decrypted.md";
        string encrypted = path;
        unsigned char password_char[crypto_box_SEEDBYTES];

        std::ofstream outfile(decrypted);

        Encripsion encripsion;
        string hast_key = _key;
        encripsion.hash_string(hast_key);

        outfile << hast_key << std::endl;

        outfile.close();

        std::copy(_key.begin(), _key.end(), password_char);

        std::clog << "password_char1 " << password_char << std::endl;

        if (hash_file_metod(encrypted.c_str(), decrypted.c_str(), password_char) != 0)
        {
            std::clog << "Error hash_file_metod" << std::endl;
        }

        std::clog << "password_char2 " << password_char << std::endl;

        old_locasion = path;
        path = decrypted;
    }
};

class FileHandle
{

private:
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

    void open_password_file(string path)
    {
        std::cout << "Opening a file" << std::endl;

        std::ifstream ifile;
        ifile.open(pathOfPassFile);

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

            std::ofstream ofile(pathOfPassFile);

            string password;
            std::cout << "new Password for file" << std::endl;
            std::cin >> password;

            // unsigned char *password_char = reinterpret_cast<unsigned char *>(*password.c_str());

            Encripsion::gen_file(password, path);

            ofile.close();
            // TODO Save the password to the file;
        }

        ifile.close();

        std::clog << "open_password_file secses" << std::endl;
    }

    void take_password_from_user(string &password)
    {
        inputCheck(pathOfPassFile);

        std::cout << "Hello" << std::endl
                  << "Please previde a password for the file: " << password << std::endl;

        std::cin >> password;

        std::cout << "Hello" << std::endl
                  << "Please previde a password for the file: " << password << std::endl;
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

    string decrypted = "/tmp/decrypted.md";

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

    char get_user_disision()
    {
        char return_string;
        std::cout << "Select one profile: S, "
                  << "Edit one profile: E, "
                  << "Delete one profile: D, "
                  << "Add new profiofile: A, "
                  << "Qwite aplicasion: Q "
                  << std::endl;
        std::cin >> return_string;

        tolower(return_string);
        return return_string;
    }

    void Select()
    {
    }
    void Edit()
    {
    }
    void Delete()
    {
    }
    void Add()
    {

        std::ofstream outfile(decrypted, std::ios::app);
        int id;
        string name,
            username,
            password;

        std::cout << "give id: ";
        std::cin >> id;

        std::cout << "give name: ";
        std::cin >> name;

        std::cout << "give username: ";
        std::cin >> username;

        std::cout << "give password: ";
        std::cin >> password;

        outfile << id << "\t" << name << "\t" << username << "\t" << password << "\t" << std::endl;
        std::cin >> password;
        outfile.close();
    }
    void Qwite()
    {
        Error::BigExit(0);
    }
};

string FileHandle::password;
string FileHandle::pathOfPassFile;
string FileHandle::hashed_password_from_file;
string FileHandle::hashed_password_from_user;
string Encripsion::old_locasion;
unsigned char *Encripsion::p_key;

int main(int argc, char const *argv[])
{
    FileHandle fileHandle(argv[1]);
    Encripsion encripsion;
    string key = "";

    if (sodium_init() < 0)
    {
        Error::BigExit(2);
    }

    if (argc != 2)
    {
        Error::BigExit(1);
    }



    // fileHandle.open_password_file(fileHandle.pathOfPassFile);

    // fileHandle.take_password_from_user(key);

    // string h = "Password";
    // std::copy(h.begin(), h.end(), key);

    //  encripsion.unhash_file(key, fileHandle.pathOfPassFile);

    // InDataBase inDataBase;
    // inDataBase.print_all_words();

    // char user_disision = inDataBase.get_user_disision();
    // if (user_disision == 's')
    // {
    // }
    // else if (user_disision == 'e')
    // {
    // }
    // else if (user_disision == 'd')
    // {
    // }
    // else if (user_disision == 'a')
    // {
    //     inDataBase.Add();
    // }

    // string cin;
    // std::cin >> cin;

    // encripsion.hash_file(key);

    // ToDo Some how get a key form the password
    // TODO The hash password can be used as a seed for the oder passwords. The last n digets are the seed for the incripsion. Anyone can't read the password widaut the main password hash

    // TODO whate for the user to diside what to do, does he want to get a pasword or does he wnat to add new one, or edit, or removie

    std::cout << "Done"
              << "\n";
    return 0;
}
