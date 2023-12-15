#include <iostream>
#include <fstream>
#include <string>
#include <stdint.h>

using std::string;

class Encripsion
    {
        public:

        static void openATheFileWithPassword() {
            std::cout << "Opens a file serech" << std::endl;
            }

        static uint32_t hash_string(const char* s) {
            uint32_t hash = 0;

            for (; *s; ++s)
                {
                hash += *s;
                hash += (hash << 10);
                hash ^= (hash >> 6);
                }

            hash += (hash << 3);
            hash ^= (hash >> 11);
            hash += (hash << 15);

            return hash;
            }
    };

class FileHandle
    {

        private:
        string pathOfPassFile;

        bool checkIfItsMyFile(string str) {
            std::cout << str;
            return true;
            }

        void inputCheck(string file) {
            std::ifstream ifile;
            ifile.open(file);

            string s;

            std::getline(ifile, s);
            checkIfItsMyFile(s);
            }

        public:
        void givePassword() {
            string temp;
            string password;

            inputCheck(pathOfPassFile);

            std::cout << "Hello" << std::endl
                << "Peazz previde a password: " << std::endl;
            std::cin >> password;
            std::cout << password << std::endl;
            password = Encripsion::hash_string(password.c_str());
            std::cout << password << std::endl;
            Encripsion::openATheFileWithPassword();

            }

        FileHandle(string path) {
            pathOfPassFile = path;
            }
    };

int main(int argc, char const* argv[]) {

    if (argc != 2)
        {
        std::cout << "Pleaz give path"
            << "\n";
        return 0;
        }

    FileHandle fileHandle(argv[1]);

fileHandle.givePassword();

    std::cout << argc << "\n";
    return 0;
    }