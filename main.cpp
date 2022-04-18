#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "aes/aes.hpp"
#include "sha256/sha256.hpp"
#include "funcs.hpp"

void wait(){
    std::string temp;
    std::getline(std::cin, temp);
    system("cls");
}

int main(){

    setup();

    std::string stoPass;
    std::string key;
    std::string salt;
    bool passLgPg = false;
    bool alive = true;
    std::string pass;
    std::string option;
    std::string curDir = "";
    std::string curDisDir = "";

    // login/signup page
    if (gStoredPass(stoPass, salt)){
        // log in
        while (!passLgPg){
            std::cout << "Enter your password: ";
            std::getline(std::cin, pass);
            if (stoPass == sha256(pass + salt, 100000)){
                std::cout << "Logged in!\n";
                passLgPg = true;
            } else {
                std::cout << "Wrong password!\n";
            }
        }
    } else {
        // sign up
        while (!passLgPg){
            std::cout << "Enter a password: ";
            std::getline(std::cin, pass);
            if (pass.size() <= 32){
                stoNewPass(pass);
                std::cout << "Logged in!\n";
                passLgPg = true;
            } else {
                std::cout << "Password cannot be longer than 32 characters!\n";
            }
        }
    }
    gStoredKey(key, pass);
    system("cls");

    while (alive){
        std::cout << 
        "RFS Console Prototype\n"
        "exit - Exit the program\n"
        "storefl - Store a new file\n"
        "storefd - Store a folder\n"
        "show - Show all stored files\n"
        "move - Move into or out of a folder\n"
        "open - Open a file\n"
        "delfl - Delete a file\n"
        "delfd - Delete a folder\n"
        "changepass - Change your password\n"
        ">>> ";
        std::getline(std::cin, option);
        system("cls");
        if (option == "exit"){
            alive = false;
        } else if (option == "storefl"){
            std::string sFilePath, sFileFd;
            std::cout << "Path to stored file: ";
            std::getline(std::cin, sFilePath);
            std::cout << "Folder to store in: ";
            std::getline(std::cin, sFileFd);
            stoFile(sFilePath, curDisDir + "/" + sFileFd, key);
            std::cout << "Stored file!\n";
            wait();
        } else if (option == "storefd"){
            std::string sFdPath;
            std::cout << "Path to stored folder: ";
            std::getline(std::cin, sFdPath);
            stoFd(sFdPath, curDisDir, sFdPath, key);
            std::cout << "Stored folder!\n";
            wait();
        } else if (option == "show"){
            std::vector<std::string> sAll = gStoredAll(curDir, key);
            std::cout << "Current folder: " << curDisDir << " (" << curDir << ")\n";
            for (std::string dat: sAll){
                std::cout << " | " << dat << "\n";
            }
            wait();
        } else if (option == "move"){
            std::string newFd;
            std::cout << "$OUT to exit current folder, or enter folder to enter: ";
            std::getline(std::cin, newFd);
            movFd(newFd, curDir, curDisDir, key);
            std::cout << "Moved!\n";
            wait();
        } else if (option == "open"){
            std::string sFilename;
            std::cout << "Enter file name: ";
            std::getline(std::cin, sFilename);
            oFile(sFilename, curDir, key);
            std::cout << "Opened!\n";
            wait();
        } else if (option == "delfl"){
            std::string dFilename;
            std::cout << "Enter file name to delete: ";
            std::getline(std::cin, dFilename);
            delFl(dFilename, curDir, key);
            std::cout << "Deleted!\n";
            wait();
        } else if (option == "delfd"){
            std::string dFdname;
            std::cout << "Enter file name to delete: ";
            std::getline(std::cin, dFdname);
            delFd(dFdname, curDir, key);
            std::cout << "Deleted!\n";
            wait();
        } else if (option == "changepass"){
            std::string nPass;
            bool valPass = false;
            while (!valPass){
                std::cout << "Enter a password: ";
                std::getline(std::cin, nPass);
                if (pass.size() <= 32){
                    reKey(nPass, pass);
                    stoNewPass(nPass);
                    gStoredKey(key, nPass);
                    pass = nPass;
                    valPass = true;
                } else {
                    std::cout << "Password cannot be longer than 32 characters!\n";
                    wait();
                }
            }
            std::cout << "Password changed!\n";
            wait();
        }
    }

}