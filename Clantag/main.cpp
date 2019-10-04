#include "memory.h"
#include <vector>
#include <fstream>

using namespace std;

DWORD enginedll;
DWORD enginedll_size;

int value = 1;

/*Я не уверен, что код андетектед, используйте на свой страх и риск. Автор: ripple. Дискорд: ripple#1337*/

void SetClanTag(const char* tag, const char* name)
{
	unsigned char Shellcode[] =
		"\x51"                    //push ecx 
		"\x52"                    //push edx 
		"\xB9\x00\x00\x00\x00"    //mov ecx,00000000 { 0 } 
		"\xBA\x00\x00\x00\x00"    //mov edx,00000000 { 0 } 
		"\xE8\x00\x00\x00\x00"    //call 0 
		"\x83\x04\x24\x0A"        //add dword ptr [esp],0A { 10 } 
		"\x68\x00\x00\x00\x00"    //push engine.dll+9AC90 
		"\xC3"                    //ret 
		"\x5A"                    //pop edx 
		"\x59"                    //pop ecx 
		"\xC3"                    //ret 
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //reserve memory[0x10] 
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //reserve memory[0x10] 
		;

	static unsigned int SHELLCODE_SIZE = sizeof(Shellcode) - 0x21;
	unsigned int TAG_SIZE = (strlen(tag) > 15) ? 15 : strlen(tag);
	unsigned int NAME_SIZE = (strlen(name) > 15) ? 15 : strlen(name);
	unsigned int DATA_SIZE = TAG_SIZE + NAME_SIZE + 2;

	LPVOID pShellCodeAdress = VirtualAllocEx(
		memory->process,
		0,
		SHELLCODE_SIZE + DATA_SIZE,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	DWORD tagAdress = (DWORD)pShellCodeAdress + SHELLCODE_SIZE;
	DWORD nameAdress = (DWORD)pShellCodeAdress + SHELLCODE_SIZE + TAG_SIZE + 1;
	DWORD fnSetClanAdress = memory->grabSig(enginedll, enginedll_size, (PBYTE)"\x53\x56\x57\x8B\xDA\x8B\xF9\xFF\x15", "xxxxxxxxx");  //Engine.dll + 0x9AC90 

	memcpy(Shellcode + 0x3, &tagAdress, sizeof(DWORD));
	memcpy(Shellcode + 0x8, &nameAdress, sizeof(DWORD));
	memcpy(Shellcode + 0x16, &fnSetClanAdress, sizeof(DWORD));
	memcpy(Shellcode + SHELLCODE_SIZE, tag, TAG_SIZE);
	memcpy(Shellcode + SHELLCODE_SIZE + TAG_SIZE + 1, name, NAME_SIZE);

	WriteProcessMemory(memory->process, pShellCodeAdress, Shellcode, SHELLCODE_SIZE + DATA_SIZE, 0);

	HANDLE hThread = CreateRemoteThread(memory->process, NULL, NULL, (LPTHREAD_START_ROUTINE)pShellCodeAdress, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(memory->process, pShellCodeAdress, 0, MEM_RELEASE);
}

void main()
{
	static string sClanTagList[999];
	static int sClanTagCount = 0;
	static string sClantag = "";
	static int iDelay = 0;

	static bool bIsOn = true;

	memory->Process("csgo.exe");
	enginedll = memory->module("engine.dll");
	enginedll_size = memory->moduleSize("engine.dll");

	printf("Custom Clantag by NiceL\n\n");
	printf("Press DELETE for Enable or Disable\n");


	std::ifstream FileClanTag;

	{
		static int i1 = 0;

		FileClanTag.open("ClanTags.txt", std::ios::in);
		char cBuf[64];

		if (!FileClanTag.is_open())
			return;

		FileClanTag.getline(cBuf, 64); // считывание задержку до "
		iDelay = std::atoi(cBuf);

		FileClanTag.getline(cBuf, 64, '"'); // переход до первой ", поставив курсор вперед, где будет клантег
		while (!FileClanTag.eof())
		{
			FileClanTag.getline(cBuf, 64, '"'); // считывание клантега до "
			sClanTagList[i1] = cBuf;

			sClanTagCount++;
			i1++;

			FileClanTag.getline(cBuf, 64, '"'); // переход на новую строку до ", поставив курсор вперед, где будет клантег
		}
	}

	while (true)
	{
		static int i2 = 0;

		if ((GetAsyncKeyState(VK_DELETE) & 0x1))
			bIsOn = !bIsOn;

		if (bIsOn)
		{
			sClantag = sClanTagList[i2];
			SetClanTag(sClantag.c_str(), "lol");
			Sleep(iDelay);

			i2++;
			if (i2 >= sClanTagCount)
				i2 = 0;
		}
		else
		{
			if (sClantag.size() > 0)
			{
				sClantag = "";
				SetClanTag(sClantag.c_str(), "lol");
			}

			Sleep(100);
		}
	}
}
