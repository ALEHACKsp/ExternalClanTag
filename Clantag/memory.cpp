#include "memory.h"

C_Memory* memory = new C_Memory();

C_Memory::C_Memory()
{

}
C_Memory::~C_Memory()
{
	CloseHandle(process);
}

void C_Memory::Process(char* name)
{
	HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(ProcEntry);

	do
		if (!strcmp(ProcEntry.szExeFile, name))
		{
			PID = ProcEntry.th32ProcessID;
			CloseHandle(hPID);

			process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
			return;
		}
	while (Process32Next(hPID, &ProcEntry));

	printf("CSGO Proccess not found!\nOpen CSGO First, then open the .exe\n");
	system("pause");
	exit(0);
}

DWORD C_Memory::module(char* name)
{
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(mEntry);

	do
		if (!strcmp(mEntry.szModule, name))
		{
			CloseHandle(hModule);
			return (DWORD)mEntry.modBaseAddr;
		}
	while (Module32Next(hModule, &mEntry));

	return 0;
}

DWORD C_Memory::moduleSize(char* name)
{
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(mEntry);

	do
		if (!strcmp(mEntry.szModule, name))
		{
			CloseHandle(hModule);
			return (DWORD)mEntry.modBaseSize;
		}
	while (Module32Next(hModule, &mEntry));

	return 0;
}

bool DataCompare(BYTE* data, BYTE* sign, char* mask)
{
	for (; *mask; mask++, sign++, data++)
	{
		if (*mask == 'x' && *data != *sign)
		{
			return false;
		}
	}
	return true;
}

DWORD C_Memory::grabSig(DWORD base, DWORD size, BYTE* sign, char* mask)
{
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	DWORD offset = 0;
	while (offset < size)
	{
		VirtualQueryEx(process, (LPCVOID)(base + offset), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (mbi.State != MEM_FREE)
		{
			BYTE* buffer = new BYTE[mbi.RegionSize];
			ReadProcessMemory(process, mbi.BaseAddress, buffer, mbi.RegionSize, NULL);
			for (int i = 0; i < mbi.RegionSize; i++)
			{
				if (DataCompare(buffer + i, sign, mask))
				{
					delete[] buffer;
					return (DWORD)mbi.BaseAddress + i;
				}
			}

			delete[] buffer;
		}
		offset += mbi.RegionSize;
	}
	return 0;
}