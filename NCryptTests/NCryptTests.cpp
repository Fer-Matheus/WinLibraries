#include <Windows.h>
#include <atlstr.h>
#include <ncrypt.h>
#pragma comment(lib, "ncrypt.lib")

using namespace std;

#define NO_MORE_ITEMS -2146893782

#define Error(status) if (status != 0) cout << "Error Code: " << hex << status << endl;

#define LOG(message) cout << message << endl;

#include <iostream>

NCRYPT_PROV_HANDLE pHandle;
NCRYPT_KEY_HANDLE kHandle;
SECURITY_STATUS status;
NCryptKeyName* keys;
PVOID temp = NULL;
bool createKey = true;

void CreateKey() {
    cout << "Starting key creating flow\n\n";

    cout << "Opening Storage provider (PCP)...\n\n";
    status = NCryptOpenStorageProvider(&pHandle, L"Microsoft Platform Crypto Provider", 0);
    Error(status);

    status = NCryptCreatePersistedKey(pHandle, &kHandle, L"RSA", L"TPM", 0, NCRYPT_OVERWRITE_KEY_FLAG);
    cout << "Creating Key...\n\n";
    Error(status);

    cout << "Defining key usage property...\n\n";
    status = NCryptSetProperty(kHandle, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)NCRYPT_ALLOW_ALL_USAGES, NCRYPT_MAX_PROPERTY_DATA, 0);

    cout << "Finalizing the key in the provider (PCP)...\n\n";
    status = NCryptFinalizeKey(kHandle, 0);

    cout << "Key creating flow success\n\n";
    Error(status);
}

void RetrieveKey() {
    cout << "Retrieving key flow\n\n";

    cout << "Opening Storage provider (PCP)...\n\n";
    status = NCryptOpenStorageProvider(&pHandle, L"Microsoft Platform Crypto Provider", 0);
    Error(status);

    cout << "Opening key from the provider (PCP)...\n\n";
    status = NCryptOpenKey(pHandle, &kHandle, L"7b83e0bc-e218-400c-8a73-7b9139901193", 0, 0);
    Error(status);

    cout << "Validating recovery key...\n\n";
    if (NCryptIsKeyHandle(kHandle) ? cout << "Valid key!" << endl : cout << "Invalid key!" << endl);
}

void EnumKeys() {
    status = NCryptOpenStorageProvider(&pHandle, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    Error(status);

    do
    {
        status = NCryptEnumKeys(pHandle, NULL, &keys, &temp, 0);

        LOG(CW2A(keys->pszName));
        LOG(CW2A(keys->pszAlgid));
        LOG("");

    } while (status != NO_MORE_ITEMS);
}

int main()
{

    CreateKey();
    RetrieveKey();
    EnumKeys();

    NCryptFreeObject(pHandle);
    NCryptFreeObject(kHandle);
    NCryptFreeBuffer(keys);
}