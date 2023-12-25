#include <iostream>
#include <fstream>
#include <string.h>
#include <sodium.h>
#include <stdint.h>

using std::string;

class Encripsion
{
public:

    void hash_string(const char* s)
    {
        // https://doc.libsodium.org/password_hashing/default_phf

        unsigned char salt[crypto_pwhash_SALTBYTES];
        unsigned char key[crypto_box_SEEDBYTES];
        char hashed_password[crypto_pwhash_STRBYTES];

        randombytes_buf(salt, sizeof salt);

        if (crypto_pwhash
        (
            key,
            sizeof key,
            s,
            strlen(s),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT
        ) != 0) {

            /* out of memory */
            std::clog << "out of memory:" << std::endl;
            exit(3);
        }

        if (crypto_pwhash_str
        (hashed_password, s, strlen(s),
            crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        }

        if (PasswordCheck(hashed_password, s)) {
            exit(4);
        }
    }

    bool PasswordCheck(char hashed_password[128], const char* s)
    {
        if (crypto_pwhash_str_verify
        (hashed_password, s, strlen(s)) != 0) {
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

    string hashed_password_from_file;

    string pathOfPassFile;

    void checkIfItsMyFile(string str)
    {
        std::ifstream ifile;
        ifile.open(str);

        if (!ifile.is_open()) {

            std::cout << "File not found" << std::endl;

            char ats;

            std::cout << "Do you want to craite a new password DataBase? Y/N" << std::endl;

            std::cin >> ats;

            if (tolower(ats) == 'n') {
                exit(0);
            }

            std::ofstream ofile(str);

            string password;
            std::cout << "new Password for file" << std::endl;
            std::cin >> password;

            Encripsion encripsion;
            char* passwordChar = password.data();

            encripsion.hash_string(passwordChar);

            std::cout << passwordChar;

            ofile << passwordChar << std::endl;
            ofile.close();
//TODO Save the password to the file;

        }

        string s;

        std::getline(ifile, s);
    }


    void inputCheck(string file)
    {
        std::ifstream ifile;
        ifile.open(file);

        string s;

        std::getline(ifile, s);
    }

public:
    string password;

    void open_password_file()
    {
        std::cout << "Opening a file" << std::endl;
        checkIfItsMyFile(pathOfPassFile);
    }

    void take_password_from_user()
    {
        inputCheck(pathOfPassFile);

        std::cout << "Hello" << std::endl
            << "Please previde a password: " << std::endl;

        std::cin >> password;
    }

    FileHandle(string path)
    {
        pathOfPassFile = path;
    }
};

int main(int argc, char const* argv[])
{
    FileHandle fileHandle(argv[1]);
    Encripsion encripsion;

    if (sodium_init() < 0) {
        std::cerr << "sodium is not initialized" << "\n";
        return 2;
    }

    if (argc != 2)
    {
        std::cerr << "Please give path" << "\n";
        return 1;
    }
    fileHandle.open_password_file();

    fileHandle.take_password_from_user();

    encripsion.hash_string(fileHandle.password.c_str());

    // TODO The hash password can be used as a seed for the oder passwords. With out main passwords oder passwords won't be understandibals

// std::cout << argc << "\n";
    return 0;

}