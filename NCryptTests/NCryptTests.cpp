#include <iostream>
#include <windows.h>
#include <atlstr.h>
#include <ncrypt.h>
#pragma comment(lib, "ncrypt.lib")

int main()
{
    // Variáveis de apoio
    DWORD countProviders;
    NCryptProviderName* providers;
    

    auto status = NCryptEnumStorageProviders(&countProviders, &providers, 0);
    if (status != 0) {
        std::cout << "Error: " << std::hex << status << std::endl;
    }

    for (int i = 0; i < countProviders; i++) {
        std::cout << "Provider " << i <<": " << CW2A(providers[i].pszName)<<std::endl;
    }

    int op;
    std::cout << "\nChoose one of the providers above" << std::endl;
    std::cin >> op;

    auto providerName = providers[op].pszName;

    NCRYPT_PROV_HANDLE pHandle;
    NCryptKeyName* keys;
    PVOID temp = NULL;

    status = NCryptOpenStorageProvider(&pHandle, providerName, 0);
    if (status != 0) {
        std::cout << "Error: " << std::hex << status << std::endl;
    }

    std::cout << "Success" << std::endl;
    
    status = NCryptEnumKeys(pHandle, NULL, &keys, &temp, 0);
    if (status != 0) {
        std::cout << "Error: " << std::hex << status << std::endl;
    }

    std::cout << "Success" << std::endl;

    std::cout << "Key pszName: " << CW2A(keys[0].pszName) << std::endl;
    std::cout << "Key Algorithm: " << CW2A(keys[0].pszAlgid) << std::endl;

    NCRYPT_KEY_HANDLE kHandle;

    status = NCryptOpenKey(pHandle, &kHandle, keys[0].pszName, 0, 0);
    if (status != 0) {
        std::cout << "Error: " << std::hex << status << std::endl;
    }

    std::cout << "Success" << std::endl;
    std::cout << "KeyHandle: " << kHandle << std::endl;

    NCryptFreeBuffer(providers);
    NCryptFreeBuffer(keys);
    NCryptFreeObject(pHandle);
    NCryptFreeObject(kHandle);
}

