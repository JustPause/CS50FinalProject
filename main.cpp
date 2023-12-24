#include <iostream>
#include <fstream>
#include <string.h>
#include <sodium.h>
#include <stdint.h>

using std::string;
static string hashed_password_global;
class Encripsion
{
public:

    static void hash_string(const char* s)
    {
        // https://doc.libsodium.org/password_hashing/default_phf

#define KEY_LEN crypto_box_SEEDBYTES

        unsigned char salt[crypto_pwhash_SALTBYTES];
        unsigned char key[KEY_LEN];

        randombytes_buf(salt, sizeof salt);

        if (crypto_pwhash
        (key, sizeof key, s, strlen(s), salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT) != 0) {

            /* out of memory */
            std::clog << "out of memory:" << std::endl;
            exit(3);
        }

        if (password_verify("password", s)) {
            exit(4);
        }

    }

    static bool password_verify(char hashed_password[128], const char* s)
    {
        if (crypto_pwhash_str_verify
        (hashed_password, s, strlen(s)) != 0) {
            /* wrong password */
            std::clog << "wrong password:" << std::endl;
            return true;
        }
        return false;

    }
    static bool password_verify(const char* s)
    {
        if (crypto_pwhash_str_verify
        (hashed_password_global.c_str(), s, strlen(s)) != 0) {
            /* wrong password */
            std::clog << "wrong password:" << std::endl;
            return true;
        }
        return false;

    }
};

class FileHandle
{

private:
    string pathOfPassFile;

    void open_password_file()
    {
        std::cout << "Opens a file serech " << std::endl;
        checkIfItsMyFile(pathOfPassFile);
    }

    static void checkIfItsMyFile(string str)
    {
        std::ifstream ifile;
        ifile.open(str);

        string s;

        std::getline(ifile, s);
        std::cout << hashed_password_global << std::endl;
        // std::cout << s << " " << Encripsion::password_verify(s.c_str()) << std::endl;

    }

    void inputCheck(string file)
    {
        std::ifstream ifile;
        ifile.open(file);

        string s;

        std::getline(ifile, s);
    }

public:
    void givePassword()
    {

        string password;

        inputCheck(pathOfPassFile);

        std::cout << "Hello" << std::endl
            << "Please previde a password: " << std::endl;

        std::cin >> password;

        Encripsion::hash_string(password.c_str());

        FileHandle::open_password_file();

        // TODO The hash password can be used as a seed for the oder passwords. With out main passwords oder passwords won't be understandibals

    }

    FileHandle(string path)
    {
        pathOfPassFile = path;
    }
};

int main(int argc, char const* argv[])
{

    if (sodium_init() < 0) {
        std::cerr << "sodium is not initialized" << "\n";
        return 2;
    }


    if (argc != 2)
    {
        std::cerr << "Please give path" << "\n";
        return 0;
    }

    FileHandle fileHandle(argv[1]);

    fileHandle.givePassword();

    // std::cout << argc << "\n";
    return 0;

}