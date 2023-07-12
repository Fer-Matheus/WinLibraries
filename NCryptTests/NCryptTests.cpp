#include <iostream>
#include <Tpm2.h>
#include <windows.h>
#include <atlstr.h>
#include <ncrypt.h>
#pragma comment(lib, "ncrypt.lib")

TpmCpp::TpmTbsDevice tbs;
TpmCpp::Tpm2 tpm;

void InitTPM() {
    tbs.Connect();
    tpm._SetDevice(tbs);
}

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
        std::cout << "\nError OpenStorage: " << std::hex << status << std::endl;
        return -1;
    }

    std::cout << "\nSuccess OpenStorage" << std::endl;
    
    status = NCryptEnumKeys(pHandle, NULL, &keys, &temp, 0);
    if (status != 0) {
        std::cout << "\nError EnumKeys: " << std::hex << status << std::endl;
        return -1;
    }

    std::cout << "\nSuccess EnumKeys" << std::endl;

    std::cout << "\nKey pszName: " << CW2A(keys[0].pszName) << std::endl;
    std::cout << "\nKey Algorithm: " << CW2A(keys[0].pszAlgid) << std::endl;

    NCRYPT_KEY_HANDLE kHandle;

    status = NCryptOpenKey(pHandle, &kHandle, keys[0].pszName, 0, 0);
    if (status != 0) {
        std::cout << "\nError OpenKey: " << std::hex << status << std::endl;
        return -1;
    }
    std::cout << "\nSuccess OpenKey" << std::endl;
    std::cout << "\nKeyHandle: " << kHandle << std::endl;

    DWORD trueHandleSize, trueHandleSizeBytes;

    status = NCryptGetProperty(kHandle, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY, NULL, {}, &trueHandleSizeBytes, 0);
    if (status != 0) {
        std::cout << "\nError GetProperty: " << std::hex << status << std::endl;
        return -1;
    }
    std::cout << "\nSuccess GetProperty" << std::endl;

    trueHandleSize = trueHandleSizeBytes;

    BYTE trueHandle;
    
    status = NCryptGetProperty(kHandle, NCRYPT_PCP_PLATFORMHANDLE_PROPERTY, &trueHandle, trueHandleSize, &trueHandleSizeBytes, 0);
    if (status != 0) {
        std::cout << "\nError GetProperty2: " << std::hex << status << std::endl;
        return -1;
    }
    std::cout << "\nSuccess GetProperty2" << std::endl;
    std::cout << "\nTrueHandle size (" << trueHandleSize << " )" << std::endl;

    std::cout << (void*)trueHandle << std::endl;

    InitTPM();

    auto response = tpm._AllowErrors().NV_ReadPublic(trueHandle);
    if (!tpm._LastCommandSucceeded()) {
        std::cout << "Error detected: " << TpmCpp::EnumToStr(tpm._GetLastResponseCode()) << std::endl;
        return -1;
    }
    std::cout << response.ToString() << std::endl;
    
    NCryptFreeBuffer(providers);
    NCryptFreeBuffer(keys);
    NCryptFreeBuffer(&trueHandle);
    NCryptFreeObject(pHandle);
    NCryptFreeObject(kHandle);
}

