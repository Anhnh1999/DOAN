#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include "Cryptor.h"


int main()
{
	void* dcmthai = calloc(MAX_PATH, 1);
	memcpy(dcmthai, "C:\\Users\\DuaMotChutThoi\\Desktop\\ssas.txt", strlen("C:\\Users\\DuaMotChutThoi\\Desktop\\ssas.txt"));
	cryptor::Encrypt((BYTE *)dcmthai);
	return 0;
}