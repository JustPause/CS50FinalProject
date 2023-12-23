#include <iostream>
#include <fstream>
#include <string.h>
#include <sodium.h>
#include <stdint.h>

using std::string;

class Encripsion
{
public:

    static void openATheFileWithPassword()
    {
        std::cout << "Opens a file serech" << std::endl;
    }

    static void hash_string(const char* s)
    {

        // https://doc.libsodium.org/hashing/generic_hashing

        char hashed_password[crypto_pwhash_STRBYTES];

        if (crypto_pwhash_str
        (hashed_password, s, strlen(s),
            crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
            /* out of memory */
            std::clog << "out of memory:" << std::endl;
            exit(3);
        }

        if (crypto_pwhash_str_verify
        (hashed_password, s, strlen(s)) != 0) {
            /* wrong password */
            std::clog << "wrong password:" << std::endl;
            exit(4);
        }

        std::clog << "Hash In Hash: " << hashed_password << std::endl;

    }
};

class FileHandle
{

private:
    string pathOfPassFile;

    void checkIfItsMyFile(string str)
    {
        if (strcmp(str.c_str(), "CSFinalProject") != 0) {
            std::cout << "You have selecter wrong file" << std::endl;
            exit(1);
        }
    }

    void inputCheck(string file)
    {
        std::ifstream ifile;
        ifile.open(file);

        string s;

        std::getline(ifile, s);
        checkIfItsMyFile(s);
    }

public:
    void givePassword()
    {

        string temp;
        string password;

        inputCheck(pathOfPassFile);

        std::cout << "Hello" << std::endl
            << "Please previde a password: " << std::endl;
        std::cin >> password;

        std::clog << "UnHash: " << password << std::endl;

        Encripsion::hash_string(password.c_str());

        std::clog << "Hash: " << password << std::endl;

        Encripsion::openATheFileWithPassword();

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