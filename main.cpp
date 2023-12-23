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

    static char hash_string(const char* s)
    {
        unsigned char hash[crypto_generichash_BYTES];

        // https://doc.libsodium.org/hashing/generic_hashing

        crypto_generichash(hash, sizeof hash, (const unsigned char*)s, strlen(s), NULL, 0);
        return *hash;

        // TODO UnHash The Password
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

        password = Encripsion::hash_string(password.c_str());

        std::clog << "Hash: " << password << std::endl;

        Encripsion::openATheFileWithPassword();

    }

    FileHandle(string path)
    {
        pathOfPassFile = path;
    }
};

int main(int argc, char const* argv[])
{

    if (sodium_init() < 0) {
        std::cout << "sodium is not initialized" << "\n";
        return 2;
    }


    if (argc != 2)
    {
        std::cout << "Please give path" << "\n";
        return 0;
    }

    FileHandle fileHandle(argv[1]);

    fileHandle.givePassword();

    // std::cout << argc << "\n";
    return 0;

}