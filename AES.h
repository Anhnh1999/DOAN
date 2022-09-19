#pragma once


#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>

namespace AES
{

	typedef struct
	{
		HCRYPTPROV provider;
		HCRYPTKEY keyAES;
		DWORD keyLen;
		BYTE keyBlobAES[256];

	} AEScomponent, * LPAEScomponent;


	//DWORD blockEncryptSize = 256;
	bool AESInit(HCRYPTPROV &provider, HCRYPTKEY &key, DWORD &KeyLen, BYTE keyBlobAES[256]);
}



