#include <iostream>
#include <fstream>
#include <string>

using std::string;

class Encripsion
{
private:
public:
    static void openATheFileWithPassword()
    {
    }
};

class FileHandle
{

private:
    string pathOfPassFile;

    bool checkIfItsMyFile(string str)
    {
        std::cout << str;
        return true;
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
                  << "Peazz previde a password: " << std::endl;
        std::cin >> password;

        Encripsion.openATheFileWithPassword();
    }

    FileHandle(string path)
    {
        pathOfPassFile = path;
    }
};

int main(int argc, char const *argv[])
{

    if (argc != 2)
    {
        std::cout << "Pleaz give path"
                  << "\n";
        return 0;
    }

    FileHandle fileHandle(argv[1]);

    std::cout << argc << "\n";
    return 0;
}