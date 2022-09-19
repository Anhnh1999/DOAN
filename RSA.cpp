#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include "RSA.h"


RSA::RSAcomponent rsa;



bool RSA::genRSAKey()
{
	//Generate RSA 2048 bit key
	//----------------------------------------------------------------------------------------------------------------------------------------------------------------

	if (!rsa.provider)
		return false;

	if (!CryptGenKey(rsa.provider, CALG_RSA_KEYX, RSA1024BIT_KEY * 2 | CRYPT_EXPORTABLE, &rsa.keyRSA))
		return false;
	//----------------------------------------------------------------------------------------------------------------------------------------------------------------


	//export public RSA key to the key blob
	//----------------------------------------------------------------------------------------------------------------------------------------------------------------
	if (!CryptExportKey(rsa.keyRSA, NULL, PUBLICKEYBLOB, NULL, NULL, &rsa.keyLen))
	{
		CryptDestroyKey(rsa.keyRSA);
		return false;
	}

	if (!CryptExportKey(rsa.keyRSA, NULL, PUBLICKEYBLOB, NULL, rsa.publicKey, &rsa.keyLen))
	{
		CryptDestroyKey(rsa.keyRSA);
		return false;
	}
	//----------------------------------------------------------------------------------------------------------------------------------------------------------------



	//export private RSA key to the key blob
	//----------------------------------------------------------------------------------------------------------------------------------------------------------------
	if (!CryptExportKey(rsa.keyRSA, NULL, PRIVATEKEYBLOB, NULL, NULL, &rsa.keyLen))
	{
		CryptDestroyKey(rsa.keyRSA);
		return false;
	}
	if (!CryptExportKey(rsa.keyRSA, 0, PRIVATEKEYBLOB, 0, rsa.privateKey, &rsa.keyLen))
	{
		CryptDestroyKey(rsa.keyRSA);
		return false;
	}
	//-----------------------------------------------------------------------------------------------------------------------------------------------------------------

	return true;
}

bool RSA::RSAInit()
{

	if (!CryptAcquireContextW(&rsa.provider, NULL, NULL, PROV_RSA_FULL, 0))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContextW(&rsa.provider, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	if (!RSA::genRSAKey())
	{
		CryptReleaseContext(rsa. provider, 0);
		return false;
	}

	return true;
}


bool RSA::EncryptRSA(BYTE keyAES[16])
{

	DWORD keyAESSize = 16;
	DWORD tempSize = 16;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	RSA::RSAInit();

	//encrypt AES key blob with RSA key
	//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
	if (!CryptEncrypt(rsa.keyRSA, 0, TRUE, 0, NULL, &keyAESSize, 0))
	{
		CryptDestroyKey(rsa.keyRSA);
		return false;
	}

	if (!CryptEncrypt(rsa.keyRSA, 0, TRUE, 0, keyAES, &tempSize, keyAESSize))
	{

		CryptDestroyKey(rsa.keyRSA);
		return false;
	}
	//-----------------------------------------------------------------------------------------------------------------------------------------------------------------



	//temporary write public and private RSA key to file for now 
	hFile = CreateFileA("C:\\Users\\DuaMotChutThoi\\Desktop\\keyPrivateRSA.txt", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, rsa.privateKey, rsa.keyLen, &rsa.keyLen, NULL);

	hFile = CreateFileA("C:\\Users\\DuaMotChutThoi\\Desktop\\keyPublicRSA.txt", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, rsa.publicKey, rsa.keyLen, &rsa.keyLen, NULL);

	CloseHandle(hFile);
	return true;
}