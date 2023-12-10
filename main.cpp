#include <iostream>
#include <fstream>
#include <string>

using std::string;

class FileHandle
{

private:
    string pathOfPassFile;

    void inputCheck(string file)
    {
        std::ifstream ifile; 
        ifile.open(file);

    }

public:
    void selectDB()
    {
        string temp;
        std::cout << "Hello" << std::endl
                  << "Select your .dbpass file" << std::endl;
        std::cin >> temp;
    }

    FileHandle(std::string path)
    {
        pathOfPassFile = path;
    }
};

int main(int argc, char const *argv[])
{

    FileHandle fileHandle("as");

    fileHandle.selectDB();

    std::cout << "Done\n";
    return 0;
}