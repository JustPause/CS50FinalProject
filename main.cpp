#include <stdio.h>
#include <sodium.h>
#include <iostream>
#include <string.h>
#include <fstream>
#include "main.h"
#include <vector>
#include <ctime>

#define CHUNK_SIZE 4096

using std::cin;
using std::cout;
using std::endl;
using std::string;

string decrypted = "./tmp/decrypted";
string encrypted = "./tmp/encrypted";

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
    string Password;
    std::cout << "Please provide a password." << std::endl;

    std::cin >> Password;

    return Password;
}

string hash_password(string password)
{
    std::string hash(crypto_generichash_BYTES, '\0');

    if (crypto_generichash(
            reinterpret_cast<unsigned char *>(&hash[0]), hash.size(),
            reinterpret_cast<const unsigned char *>(password.data()), password.length(),
            nullptr, 0) != 0)
    {
        std::cerr << "Error hashing string" << std::endl;
        exit(1);
    }

    return hash;
}

class Crypt
{
public:
    static void decrypt_metod(unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
    {
        if (decrypt(decrypted.data(), encrypted.data(), key) != 0)
        {
            std::cout << "decrypt error" << std::endl;
            exit(1);
        }
    }

    static void encrypt_metod(unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
    {
        if (encrypt(encrypted.data(), decrypted.data(), key) != 0)
        {
            std::cout << "encrypt error" << std::endl;
            exit(1);
        }
    }
};

class InDataBase
{
private:
    static int last_id;

    struct Passwords
    {
        int id;
        string name;
        string userName;
        string password;
    };

public:
    static void print_all_words()
    {

        int id;
        string username, name, password;
        std::vector<Passwords> password_vector;

        std::ifstream ifile(decrypted);

        int size = 0;
        std::cout << "print_all_words" << std::endl;
        while (ifile >> id >> username >> name >> password)
        {
            size++;
            std::cout << id << "\t" << username << "\t" << name << "\t" << password << std::endl;
        }
        last_id = id;
        ifile.close();
    }

    static bool get_user_disision()
    {

        bool if_exit = false;
        char charer;
        std::cout
            << "Add new profiofile: A, "
            << "Qwite aplicasion: Q "
            << std::endl;
        std::cin >> charer;

        charer = tolower(charer);

        // if (charer == 's')
        // {
        //     Select();
        // }
        // else if (charer == 'e')
        // {
        //     Edit();
        // }
        // else if (charer == 'd')
        // {
        //     Delete();
        // }
        if (charer == 'a')
        {
            Add();
        }
        else if (charer == 'q')
        {
            Qwite(if_exit);
        }
        else
        {
            cout << "you dinint select anifing" << endl;
        }

        return if_exit;
    }
    static string gen_password(int l)
    {
        string a = "";
        std::srand(std::time(nullptr));
        for (int i = 0; i < l; i++)
        {
            string randomString(1, static_cast<char>(std::rand() % 94 + 33));
            a.append(randomString);
        }
    }
    static void Select()
    {
    }
    static void Edit()
    {
    }
    static void Delete()
    {
    }
    static void Add()
    {

        std::ofstream outfile(decrypted, std::ios::app);
        int id = last_id + 1;
        string name,
            username,
            password;

        std::cout << "give name: ";
        std::cin >> name;

        std::cout << "give username: ";
        std::cin >> username;

        std::cout << "give password: ";
        std::cin >> password;

        if (password == "gen")
        {
            cout << "Can you provide the length of the password: ";
            int num;
            cin >> num;
            password = gen_password(num);
        }

        outfile << id << "\t" << name << "\t" << username << "\t" << password << "\t" << std::endl;
        outfile.close();
    }

    static void Qwite(bool &exiting)
    {
        exiting = true;
    }
};

void to_key(unsigned char key[32], std::string &key_string)
{
    for (int i = 0; i < 32; i++)
    {
        key[i] = static_cast<unsigned char>(key_string[i]);
    }
}

bool file_exits(string path)
{
    std::ifstream ifile;
    ifile.open(path);

    if (!ifile.is_open())
    {
        return false;
    }
    else
    {
        return true;
    }
}

static void gen_file()
{
    std::cout << "File not found" << std::endl;
    char ats;

    std::cout << "Do you want to craite a new password DataBase? Y/N" << std::endl;

    std::cin >> ats;

    if (tolower(ats) == 'n')
    {
        exit(0);
    }
    else if (tolower(ats) == 'y')
    {
        std::ofstream decrypt_file(decrypted);
        decrypt_file << "Hello, World!";
        decrypt_file.close();
        std::cout << "File created successfully." << std::endl;
    }
    else
    {
        exit(0);
    }
}

int InDataBase::last_id;

int main(int argc, char const *argv[])
{
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    if (sodium_init() < 0)
    {
        exit(1);
    }

    if (argc != 2)
    {
        exit(1);
    }

    encrypted = argv[1];

    if (file_exits(argv[1]))
    {
        string password = password_form_user();
        string key_string = hash_password(password);
        to_key(key, key_string);
        Crypt::decrypt_metod(key);
    }

    else
    {
        gen_file();
        string password = password_form_user();
        string key_string = hash_password(password);
        to_key(key, key_string);
    }

    InDataBase::print_all_words();

    while (!InDataBase::get_user_disision())
        InDataBase::print_all_words();
    ;

    Crypt::encrypt_metod(key);

    return 0;
}
