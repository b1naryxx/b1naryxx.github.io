#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <iostream>
#include <iomanip>
#include <fstream>
using namespace std;


 int main (int argc, LPTSTR argv []) {
    
    DWORD dwStatus = 0;
	HCRYPTPROV hCryptProv = NULL;
    HCRYPTHASH hHash;
    HCRYPTKEY  hKey;
    HANDLE hFile;

    BYTE lpBuffer[159778+1000] = "";
    DWORD sizeData = 159778 ;
    DWORD dwBytesRead = 0;

    char vcryptkey[] = "fajpenzlrumdlwphedshoydedjvdipbtxmnraijinazgnrsdpg";
    //Read data from data.bin

    hFile = CreateFile( ".\\data.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); 
    if (ReadFile(hFile, lpBuffer, 159778, &dwBytesRead, NULL)) 
    {
        printf("Copied encrypted data to memory. \n");
    }
    CloseHandle(hFile);
    
    if(CryptAcquireContext(
        &hCryptProv,               // handle to the CSP
        0,                  // container name 
        0,                      // use the default provider
        24,             // provider type
        0xF0000000))                        // flag values
    {
        printf("A cryptographic context has been acquired.\n");
    }
    if(CryptCreateHash(
        hCryptProv, 
        CALG_MD5, 
        0, 
        0, 
        &hHash)) 
    {
        printf("An empty hash object has been created. \n");
    }
    if(CryptHashData(
        hHash,
        reinterpret_cast<BYTE*>(vcryptkey),
        50,
        1))
    {
        printf("Data has been added to the hash object. \n");
    }
    if(CryptDeriveKey(
        hCryptProv,
        0x00006610,
        hHash,
        0x00000001,
        &hKey))
    {
        printf("A cryptographic session key has been derived. \n");
    }
    //CryptDestroyHash(hHash);
    if(CryptDecrypt(
        hKey,
        hHash,
        true,
        0,
        (BYTE*)lpBuffer,
        &sizeData))
    {
        printf("Data has been decrypted");
    }
    else
    {
        dwStatus = GetLastError();
        printf("CryptDecrypt failed: %#010x\n", dwStatus); 
    }
}