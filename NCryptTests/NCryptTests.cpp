#include <Windows.h>
#include <atlstr.h>
#include <ncrypt.h>
#pragma comment(lib, "ncrypt.lib")

using namespace std;

enum Algorithm
{
    RSA,
    ECDSA
};

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
int op;
string tempString;

wstring stringToWString(string someString) {

    wstring wSomeString = wstring(someString.begin(), someString.end());
    return wSomeString;
}

void CreateKey() {
    cout << "Starting key creating flow\n\n";

    cout << "Opening Storage provider (PCP)...\n\n";
    status = NCryptOpenStorageProvider(&pHandle, L"Microsoft Platform Crypto Provider", 0);
    Error(status);

    LOG("Enter a key name: ");
    cin >> tempString;
    wstring wtempString = stringToWString(tempString);

    status = NCryptCreatePersistedKey(pHandle, &kHandle, L"ECDSA", wtempString.c_str(), 0, NCRYPT_OVERWRITE_KEY_FLAG);
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

    LOG("Enter a key name: ");
    cin >> tempString;
    wstring wtempString = stringToWString(tempString);

    cout << "Opening key from the provider (PCP)...\n\n";
    status = NCryptOpenKey(pHandle, &kHandle, wtempString.c_str(), 0, 0);
    Error(status);

    cout << "Validating recovery key...\n\n";
    if (NCryptIsKeyHandle(kHandle) ? cout << "Valid key!" << endl : cout << "Invalid key!" << endl);
}

void EnumKeys() {
    temp = NULL;
    status = NCryptOpenStorageProvider(&pHandle, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    Error(status);

    while (true) {
        status = NCryptEnumKeys(pHandle, NULL, &keys, &temp, 0);

        if (status == NO_MORE_ITEMS) break;

        LOG(CW2A(keys->pszName));
        LOG(CW2A(keys->pszAlgid));
        LOG("");
    }
}

void DeleteKey() {
    cout << "Starting key deleting flow\n\n";

    cout << "Opening Storage provider (PCP)...\n\n";
    status = NCryptOpenStorageProvider(&pHandle, L"Microsoft Platform Crypto Provider", 0);
    Error(status);

    LOG("Enter a key name: ");
    cin >> tempString;
    wstring wtempString = stringToWString(tempString);

    status = NCryptOpenKey(pHandle, &kHandle, wtempString.c_str(), 0, 0);
    Error(status);

    status = NCryptDeleteKey(kHandle, 0);
    Error(status);

    LOG("Delete key success\n\n");
}

int main()
{
    bool cond = true;
    while (cond)
    {
        LOG("1 - Create a key\n");
        LOG("2 - Retrieve a key\n");
        LOG("3 - Enums the keys\n");
        LOG("4 - Delete a key\n");
        LOG("5 - Exit\n");

        cin >> op;

        switch (op)
        {
        case 1:
            system("cls");
            CreateKey();
            break;
        case 2:
            system("cls");
            RetrieveKey();
            break;
        case 3:
            system("cls");
            EnumKeys();
            break;
        case 4:
            DeleteKey();
            break;
        case 5:
            cond = false;
            break;
        default:
            break;
        }
    }

    NCryptFreeObject(pHandle);
    NCryptFreeObject(kHandle);
    NCryptFreeBuffer(keys);
}