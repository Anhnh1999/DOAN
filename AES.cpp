#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include "AES.h"



bool AES::AESInit(HCRYPTPROV &provider, HCRYPTKEY &key, DWORD &KeyLen, BYTE keyBlobAES[256])
{
	if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, 0))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET))
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	if (!provider)
	{
		CryptReleaseContext(provider, 0);
		return false;
	}
	if (!CryptGenKey(provider, CALG_AES_128, CRYPT_EXPORTABLE, &key))
	{
		CryptReleaseContext(provider, 0);
		return false;
	}
	
	
	if (!CryptExportKey(key, NULL, PLAINTEXTKEYBLOB, NULL, NULL, &KeyLen))
	{
		CryptDestroyKey(key);
		CryptReleaseContext(provider, 0);
		return false;
	}

	if(!CryptExportKey(key, NULL, PLAINTEXTKEYBLOB, NULL, keyBlobAES, &KeyLen))
	{
		CryptDestroyKey(key);
		CryptReleaseContext(provider, 0);
		return false;
	}
	return true;
}




