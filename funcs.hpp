#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <random>
#include <fileapi.h>
#include <filesystem>
#include <Windows.h>

#include "aes/aes.hpp"
#include "sha256/sha256.hpp"

#pragma once

// random variables
std::uniform_int_distribution<int> nRange(0, 61);

// folder object
class EncryptedFd{
    public:
        std::string name, iv, eName, eFdname;
        int padsize;
        EncryptedFd(std::string name, std::string iv, std::string eName, int padsize, std::string eFdname)
         : name(name), iv(iv), eName(eName), padsize(padsize), eFdname(eFdname){};
};

// file object
class EncryptedFl{
    public:
        std::string name, iv, eName, eFilename;
        int padsize, fnPadsize;
        EncryptedFl(std::string name, std::string iv, std::string eName, int padsize, std::string eFilename, int fnPadsize)
         : name(name), iv(iv), eName(eName), padsize(padsize), eFilename(eFilename), fnPadsize(fnPadsize){};
};

// split string by delimiter
std::vector<std::string> splStr(std::string raw, std::string delim){
    std::vector<std::string> sVector;
    size_t pos;
    while ((pos = raw.find(delim)) != std::string::npos){
        sVector.push_back(raw.substr(0, pos));
        raw.erase(0, pos + delim.size());
    }
    return sVector;
}

// create map files in folder if not exists
void cMapFiles(std::string folder){

    std::ifstream flMapRd(folder + "/flmap.fmap");
    std::ifstream fdMapRd(folder + "/fdmap.fmap");

    if (!flMapRd.good()){
        std::ofstream flMapFile(folder + "/flmap.fmap");
        flMapFile.close();
    }

    if (!fdMapRd.good()){
        std::ofstream fdMapFile(folder + "/fdmap.fmap");
        fdMapFile.close();
    }

    flMapRd.close();
    fdMapRd.close();

}

// get all files in current folder
std::vector<EncryptedFl> gAllFiles(std::string folder, std::string key){

    cMapFiles(folder);

    std::ifstream flMapRd(folder + "/flmap.fmap", std::ios_base::binary);
    std::string line;
    std::vector<EncryptedFl> rFiles;
    std::ostringstream ssrLines;
    std::string rLines;

    ssrLines << flMapRd.rdbuf();
    flMapRd.close();
    rLines = ssrLines.str();

    for (std::string line: splStr(rLines, ",,,")){

        if (!line.size()) continue;

        // parse line
        std::vector<std::string> pFileDat = splStr(line, "|||");

        std::string iv = pFileDat[1];
        int padsize = std::stoi(pFileDat[2]);
        int fnPadsize = std::stoi(pFileDat[4]);
        std::string eFilename = pFileDat[3];
        std::string rName = decrypt(eFilename, key, iv, fnPadsize);

        rFiles.push_back(EncryptedFl(rName, iv, pFileDat[0], padsize, eFilename, fnPadsize));

    }

    return rFiles;
}

// get all folders in current folder
std::vector<EncryptedFd> gAllFolders(std::string folder, std::string key){

    cMapFiles(folder);

    std::ifstream fdMapRd(folder + "/fdmap.fmap", std::ios_base::binary);
    std::string line;
    std::vector<EncryptedFd> rFiles;
    std::ostringstream ssrLines;
    std::string rLines;

    ssrLines << fdMapRd.rdbuf();
    fdMapRd.close();
    rLines = ssrLines.str();

    for (std::string line: splStr(rLines, ",,,")){

        if (!line.size()) continue;

        // parse line
        std::vector<std::string> pFolderDat = splStr(line, "|||");

        std::string iv = pFolderDat[1];
        int padsize = std::stoi(pFolderDat[2]);
        std::string eFdname = pFolderDat[3];
        std::string rName = decrypt(eFdname, key, iv, padsize);

        rFiles.push_back(EncryptedFd(rName, iv, pFolderDat[0], padsize, eFdname));

    }

    return rFiles;

}

// get the stored password, return bool based on whether password has been set
bool gStoredPass(std::string& sPass, std::string& sHash){

    std::ifstream pFile("password/password.pw");
    std::string pContents;

    // check if file exists
    if (!pFile.good()){

        // create file and close files
        std::ofstream tFile("password/password.pw");
        tFile.close();
        pFile.close();

        return false;
    }
    pFile >> pContents;
    pFile.close();

    if (!pContents.size()) return false;

    std::vector<std::string> vpContents = splStr(pContents, "|||");
    sPass = vpContents[0];
    sHash = vpContents[1];

    return true;
}

// get the stored key
void gStoredKey(std::string& sKey, std::string pass){

    std::ifstream kFile("password/key.key", std::ios_base::binary);

    // check if file exists
    if (!kFile.good()){

        // randomly generate new key
        std::string nKey;
        for (int i = 0; i != 30; i++){nKey += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"[nRange(rGenerator)];}
        EncryptRes eKey = encrypt(nKey, pass);
        
        // write new key
        std::ofstream tFile("password/key.key", std::ios_base::binary);
        tFile << eKey.encrypted << "|||" << eKey.iv << "|||" << eKey.rPadsize << "|||";
        tFile.close();
        kFile.close();

        sKey = nKey;
        return;
    }

    std::string kContents;
    std::ostringstream skContents;
    skContents << kFile.rdbuf();
    kContents = skContents.str();
    kFile.close();

    // parse key
    std::vector<std::string> kDat = splStr(kContents, "|||");

    // decrypt and store key
    std::string iv = kDat[1];
    int padsize = std::stoi(kDat[2]);
    std::string eKey = kDat[0];
    sKey = decrypt(eKey, pass, iv, padsize);
}

// store/rewrite the password
void stoNewPass(std::string pass){
    std::string salt;
    std::ofstream pFile("password/password.pw");
    for (int i = 0; i != 32; i++){salt += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"[nRange(rGenerator)];}
    pFile << sha256(pass + salt, 100000) << "|||" << salt << "|||";
    pFile.close();
}

// rewrite key
void reKey(std::string pass, std::string oPass){
    std::string curKey;
    EncryptRes enKey;

    gStoredKey(curKey, oPass);
    enKey = encrypt(curKey, pass);

    std::ofstream kWrite("password/key.key", std::ios_base::binary);
    kWrite << enKey.encrypted << "|||" << enKey.iv << "|||" << enKey.rPadsize << "|||";
    kWrite.close();
}

// store a file
void stoFile(std::string sFilePath, std::string folder, std::string key){

    // write to folder map and create folders if not exist
    std::vector<std::string> subFds = splStr(folder + "/", "/");
    std::string curDir = "data";
    if (folder != "/"){
        for (std::string fd: subFds){

            // check if folder name already stored
            bool create = true;
            std::string sFdname;
            for (EncryptedFd eFd: gAllFolders(curDir, key)){
                if (eFd.name == fd){
                    create = false;
                    sFdname = eFd.eName;
                }
            }
            
            if (!fd.size()) continue;

            // get new folder name using random variables from aes.hpp
            std::string nFdname;
            if (create){
                for (int i = 0; i != 16; i++){
                    nFdname += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"[nRange(rGenerator)];
                }
            } else {
                nFdname = sFdname;
            }

            // create folder if not there, open file
            std::ofstream fdMapWrite(curDir + "/fdmap.fmap", std::ios_base::app | std::ios_base::binary);
            cMapFiles(curDir);
            curDir += "/" + nFdname;
            if (create) CreateDirectory(curDir.c_str(), NULL);

            // encrypt folder name
            EncryptRes feRes = encrypt(fd, key);

            // add folder name
            if (create) fdMapWrite << nFdname << "|||" << feRes.iv << "|||" << feRes.rPadsize << "|||" << feRes.encrypted << "|||,,,";
            fdMapWrite.close();
        }
    }

    cMapFiles(curDir);

    // read file contents
    std::string fContent;
    std::ostringstream fContentBuf;
    std::ifstream sFileRead(sFilePath, std::ios_base::binary);
    fContentBuf << sFileRead.rdbuf();
    fContent = fContentBuf.str();
    sFileRead.close();

    // encrypt file contents
    EncryptRes feRes = encrypt(fContent, key);

    // get new filename using random variables from aes.hpp
    std::string nFilename;
    for (int i = 0; i != 16; i++){
        nFilename += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"[nRange(rGenerator)];
    }

    // write to new file
    std::ofstream nFileWrite(curDir + "/" + nFilename + ".encrypted", std::ios_base::binary);
    nFileWrite << feRes.encrypted;
    nFileWrite.close();

    // write to file map
    std::ofstream flMapWrite(curDir + "/flmap.fmap", std::ios_base::app | std::ios_base::binary);
    std::string cFilePath = sFilePath.substr(sFilePath.find_last_of("/\\") + 1);
    EncryptRes eFilename = encrypt(cFilePath, key, feRes.iv);
    flMapWrite << nFilename << "|||" << feRes.iv << "|||" << feRes.rPadsize << "|||" << eFilename.encrypted << "|||" << eFilename.rPadsize << "|||,,,";
    flMapWrite.close();

}

// store a folder
void stoFd(std::string sFdPath, std::string curDir, std::string fdPath, std::string key){
    for (auto& item: std::filesystem::recursive_directory_iterator(sFdPath)){
        if (item.is_regular_file()){
            std::string sFilePath = item.path().string();
            for (int i = 0; i != sFilePath.size(); i++){
                if (sFilePath[i] == '\\') sFilePath[i] = '/';
            }
            std::string folder = curDir + (curDir.size() ? "/" : "") + sFilePath.substr(0, sFilePath.find_last_of("/\\"));
            stoFile(sFilePath, folder, key);
        }
    }
}

// get stored files in folder
std::vector<std::string> gStoredAll(std::string folder, std::string key){
    std::vector<std::string> rAll;
    for (EncryptedFl eFile: gAllFiles("data" + folder, key)){
        rAll.push_back(eFile.name);
    }
    for (EncryptedFd eFd: gAllFolders("data" + folder, key)){
        rAll.push_back(eFd.name);
    }
    return rAll;
}

// move folder
void movFd(std::string newFd, std::string& curDir, std::string& curDisDir, std::string key){
    if (!curDir.size() && newFd == "$OUT") return;
    std::cout << "[DEBUG] " << "data" + curDir << "\n";
    std::vector<EncryptedFd> eFds = gAllFolders("data" + curDir, key);
    if (newFd == "$OUT"){
        curDir = curDir.substr(0, curDir.find_last_of("/"));
        curDisDir = curDisDir.substr(0, curDisDir.find_last_of("/"));
    } else {
        for (EncryptedFd eFd: eFds){
            if (eFd.name == newFd){
                curDir += "/" + eFd.eName;
                curDisDir += "/" + newFd;
                break;
            }
        }
    }
}

// open file (read-only)
void oFile(std::string sFilename, std::string folder, std::string key){
    for (EncryptedFl eFile: gAllFiles("data" + folder, key)){
        if (eFile.name == sFilename){
            // write decrypted
            std::ofstream oFileWrite("temp/" + sFilename, std::ios_base::binary);
            std::ifstream sFileRead("data" + folder + "/" + eFile.eName + ".encrypted", std::ios_base::binary);
            std::ostringstream ssContents;
            std::string sfContents;
            ssContents << sFileRead.rdbuf();
            sfContents = ssContents.str();
            oFileWrite << decrypt(sfContents, key, eFile.iv, eFile.padsize);
            sFileRead.close();
            oFileWrite.close();

            // open with associated file
            SetCurrentDirectory("temp");
            ShellExecute(0, 0, sFilename.c_str(), 0, 0, SW_SHOW);
            SetCurrentDirectory("../");

            return;
        }
    }
}

// delete file
void delFl(std::string dFilename, std::string folder, std::string key){
    std::ostringstream flMapStream;
    for (EncryptedFl eFile: gAllFiles("data" + folder, key)){
        if (eFile.name == dFilename){
            std::remove(("data" + folder + "/" + eFile.eName + ".encrypted").c_str());
            continue;
        }
        flMapStream << eFile.eName << "|||" << eFile.iv << "|||" << eFile.padsize << "|||" << eFile.eFilename << "|||" << eFile.fnPadsize << "|||,,,";
    }
    std::ofstream flMapWrite("data" + folder + "/flmap.fmap", std::ios_base::binary);
    flMapWrite << flMapStream.str();
    flMapWrite.close();
}

// delete folder
void delFd(std::string dFdname, std::string folder, std::string key){
    std::ostringstream fdMapStream;
    for (EncryptedFd eFd: gAllFolders("data" + folder, key)){
        if (eFd.name == dFdname){
            std::filesystem::remove_all(("data" + folder + "/" + eFd.eName).c_str());
            RemoveDirectory(("data" + folder + "/" + eFd.eName).c_str());
            continue;
        }
        fdMapStream << eFd.eName << "|||" << eFd.iv << "|||" << eFd.padsize << "|||" << eFd.eFdname << "|||,,,";
    }
    std::ofstream fdMapWrite("data" + folder + "/fdmap.fmap", std::ios_base::binary);
    fdMapWrite << fdMapStream.str();
    fdMapWrite.close();
}

// setup things
void setup(){
    CreateDirectory("temp", NULL);
    std::atexit([]{std::filesystem::remove_all("temp");});
}