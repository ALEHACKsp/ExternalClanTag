#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include <sstream>

class C_Memory
{
public:
	C_Memory();
	~C_Memory();

	DWORD PID;
	HANDLE process;

	virtual void Process(char* name);
	virtual DWORD module(char* name);
	virtual DWORD moduleSize(char* name);
	DWORD grabSig(DWORD base, DWORD size, BYTE* sign, char* mask);
};

extern C_Memory* memory;