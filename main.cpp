#include <iostream>
#include <fstream>
#include <string.h>
#include <sodium.h>
#include <stdint.h>
#include <memory>
#include <vector>

using std::string;

class error {
public:
    static void BigExit(int i)
    {
        std::cout << "Error " << i << std::endl;
        exit(i);
    }
};

class Encripsion
{
public:

    void hash_string(string& s)
    {
        // https://doc.libsodium.org/password_hashing/default_phf

        unsigned char salt[crypto_pwhash_SALTBYTES];
        unsigned char key[crypto_box_SEEDBYTES];
        char hashed_password[crypto_pwhash_STRBYTES];
        const char* inputPassword = s.c_str();

        randombytes_buf(salt, sizeof salt);

        if (crypto_pwhash(
            key,
            sizeof key,
            inputPassword,
            strlen(inputPassword),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT
        ) != 0) {

            /* out of memory */
            error::BigExit(3);
        }

        if (crypto_pwhash_str
        (hashed_password, inputPassword, strlen(inputPassword),
            crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        }

        if (PasswordCheck(hashed_password, inputPassword)) {
            error::BigExit(4);
        }

        s = hashed_password;

    }

    bool PasswordCheck(char hashed_password[128], const char* s)
    {
        if (crypto_pwhash_str_verify
        (hashed_password, s, strlen(s)) != 0) {
            /* wrong password */
            std::clog << "wrong password or wrong file:" << std::endl;
            return true;
        }
        std::clog << "good password:" << std::endl;
        return false;
    }

};

class FileHandle
{

private:

    string hashed_password_from_file;



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
            string passwordString = password.data();

            encripsion.hash_string(passwordString);

            ofile << passwordString << std::endl;

            std::cout << std::endl;

            ofile.close();
            //TODO Save the password to the file;

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

class InDataBase {
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

        while (ifile >> id >> username >> name >> password) {
            size++;

            password_vector.resize(size);
            password_vector[size - 1].id = id;

            std::cout << id << "\t" << username << "\t" << name << "\t" << password << std::endl;

            //ToDo Decoude couded passwords
        }
    }
};

string FileHandle::password;
string FileHandle::pathOfPassFile;

int main(int argc, char const* argv[])
{
    FileHandle fileHandle(argv[1]);
    Encripsion encripsion;

    if (sodium_init() < 0) {
        error::BigExit(2);
    }

    if (argc != 2)
    {
        error::BigExit(1);
    }

    fileHandle.open_password_file();

    fileHandle.take_password_from_user();

    fileHandle.check_user_file_password();

    InDataBase inDataBase;

    inDataBase.print_all_words();

    // encripsion.hash_string(fileHandle.password);

    // TODO The hash password can be used as a seed for the oder passwords. With out main passwords oder passwords won't be understandibals

    //TODO whate for the user to diside what to do, does he want to get a pasword or does he wnat to add new one, or edit, or removie

// std::cout << argc << "\n";
    return 0;

}
