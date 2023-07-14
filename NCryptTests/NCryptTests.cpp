#include <iostream>
#include <windows.h>
#include <atlstr.h>
#include <ncrypt.h>
#pragma comment(lib, "ncrypt.lib")
#include <bcrypt.h>
#include "NCryptTests.h"
#pragma comment(lib, "bcrypt.lib")

bool run = true;
int op;
std::string keyName, algName;
DWORD countProviders;
NCryptProviderName* providers;
NCRYPT_PROV_HANDLE pHandle;
NCryptKeyName* keys;
PVOID temp = NULL;
NCRYPT_KEY_HANDLE kHandle;
SECURITY_STATUS status;

void ChooseProvider() {
     status = NCryptEnumStorageProviders(&countProviders, &providers, 0);
    if (status != 0) {
        std::cout << "Error EnumStorageProviders: " << std::hex << status << std::endl;
    }

    for (int i = 0; i < countProviders; i++) {
        std::cout << "Provider " << i << ": " << CW2A(providers[i].pszName) << std::endl;
    }

    int option;
    std::cout << "\nChoose one of the providers above" << std::endl;
    std::cin >> option;

    auto providerName = providers[option].pszName;

    status = NCryptOpenStorageProvider(&pHandle, providerName, 0);
    if (status != 0) {
        std::cout << "\nError OpenStorage: " << std::hex << status << std::endl;
        exit(-1);
    }

    std::cout << "\nSuccess OpenStorage" << std::endl;
    Sleep(3000);
}

void EnumKeys()
{
    status = NCryptEnumKeys(pHandle, NULL, &keys, &temp, NCRYPT_MACHINE_KEY_FLAG);
    if (status != 0 && status != -2146893782) {
        std::cout << "\nError EnumKeys: " << status << std::endl;
        exit(-1);
    }
    std::cout << "\nSuccess EnumKeys" << std::endl;

    std::cout << "\nKey pszName: " << CW2A(keys[0].pszName) << std::endl;
    std::cout << "\nKey Algorithm: " << CW2A(keys[0].pszAlgid) << std::endl;
    Sleep(3000);
}

void OpenKey()
{
    status = NCryptOpenKey(pHandle, &kHandle, keys[0].pszName, 0, 0);
    if (status != 0) {
        std::cout << "\nError OpenKey: " << std::hex << status << std::endl;
        exit(-1);
    }
    std::cout << "\nSuccess OpenKey" << std::endl;
    std::cout << "\nKeyHandle: " << kHandle << std::endl;
    std::cout << "Was a valide key? " << (NCryptIsKeyHandle(kHandle) ? "True" : "False") << std::endl;
    Sleep(3000);
}
void OpenKey(std::string keyName)
{
    std::wstring keyNameW = std::wstring(keyName.begin(), keyName.end());
    status = NCryptOpenKey(pHandle, &kHandle, keyNameW.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG);
    if (status != 0) {
        std::cout << "\nError OpenKey: " << std::hex << status << std::endl;
        exit(-1);
    }
    std::cout << "\nSuccess OpenKey" << std::endl;
    std::cout << "\nKeyHandle: " << kHandle << std::endl;
    std::cout << "Was a valide key? " << (NCryptIsKeyHandle(kHandle) ? "True" : "False") << std::endl;
    Sleep(3000);
}

void CreateKey(std::string keyName, std::string algName)
{
    
    std::wstring keyNameW = std::wstring(keyName.begin(), keyName.end());
    status = NCryptCreatePersistedKey(pHandle, &kHandle, (algName == "RSA" ? NCRYPT_RSA_ALGORITHM : NCRYPT_ECDSA_ALGORITHM), keyNameW.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG);
    if (status != 0) {
        std::cout << "\nError CreatePersistedKey: " << std::hex << status << std::endl;
        exit(-1);
    }

    status = NCryptFinalizeKey(kHandle, NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG);
    if (status != 0) {
        std::cout << "\nError FinalizeKey: " << std::hex << status << std::endl;
        exit(-1);
    }

    std::cout << "Success CreatePersistedKey" << std::endl;
    Sleep(3000);
}

void Encrypt() {
    BYTE data = (BYTE)54657374; // Hex ("Test")
    DWORD dataSize;

    BYTE encryptedData;

    BCRYPT_OAEP_PADDING_INFO padding;

    status = NCryptEncrypt(kHandle, &data, sizeof(data), NULL, NULL,NULL, &dataSize, 0);
    if (status != 0) {
        std::cout << "\nError get encrypt size: " << std::hex << status << std::endl;
        exit(-1);
    }

    status = NCryptEncrypt(kHandle, &data, sizeof(data), &padding, &encryptedData, dataSize, NULL, NCRYPT_PAD_OAEP_FLAG);
    if (status != 0) {
        std::cout << "\nError EnCrypt: " << std::hex << status << std::endl;
        exit(-1);
    }

    std::cout << "Success Encrypt" << std::endl;
    std::cout << "Data: " << (void*)data << std::endl;
    std::cout << "EncryptedData: " << (void*)encryptedData << std::endl;
}

int main()
{
    while (run) {
        std::cout << "\n1 - List and choose a storage provider"<< std::endl;
        std::cout << "2 - Enumerate the keys in the storage provider" << std::endl;
        std::cout << "3 - Open a default key for the storage provider" << std::endl;
        std::cout << "4 - Open a specified key for the storage provider" << std::endl;
        std::cout << "5 - Create a new PersistedKey" << std::endl;
        std::cout << "6 - Encrypt some data" << std::endl;
        std::cout << "7 - Exit program" << std::endl;
        std::cin >> op;
        switch (op)
        {
        case 1: 
            ChooseProvider();
            break;
        case 2:
            EnumKeys();
            break;
        case 3:
            OpenKey();
            break;
        case 4:
            
            std::cout << "Enter the keyName: ";
            std::cin >> keyName;
            OpenKey(keyName);
            keyName.clear();
            break;
        case 5:
            std::cout << "Enter the keyName: ";
            std::cin >> keyName;
            std::cout << "Enter the algName (RSA or ECDSA): ";
            std::cin >> algName;
            CreateKey(keyName, algName);
            keyName.clear();
            algName.clear();
            break;
        case 6: 
            Encrypt();
            break;
        case 7: 
            run = false;
            break;
        default:
            break;
        }
        system("cls");
    }
    NCryptFreeBuffer(providers);
    NCryptFreeBuffer(keys);

    NCryptFreeObject(pHandle);
    NCryptFreeObject(kHandle);
}

