#pragma once

#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>


namespace RSA
{

	typedef struct
	{
		HCRYPTKEY keyRSA;
		HCRYPTPROV provider;
		BYTE publicKey[2048];
		BYTE privateKey[2048];

		DWORD keyLen;

	} RSAcomponent, *LPRSAcomponent;


	bool genRSAKey();
	bool RSAInit();
	bool EncryptRSA(BYTE keyAES[16]);

}


