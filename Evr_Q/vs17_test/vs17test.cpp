#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include "smc.h"
#include "Anti-Debug.h"
#include "scode.h""
#include "scode1.h"
#include "scode2.h"
#include "scode3.h"

#pragma comment(linker, "/INCLUDE:__tls_used");
void lookupprocess()
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // 在快照中包含系统中所有的进程
	BOOL bMore = Process32First(hProcessSnap, &pe32); // 获得第一个进程的句柄
	while (bMore)
	{
		_wcslwr_s(pe32.szExeFile, wcslen(pe32.szExeFile)+1);
		if (!wcscmp(pe32.szExeFile, L"ollyice.exe"))
		{
			printf("///////WARNING///////\n");
			exit(0);
		}
		if (!wcscmp(pe32.szExeFile, L"ollydbg.exe"))
		{
			printf("///////\nWARNING\n///////\n");
			exit(0);
		}
		if (!wcscmp(pe32.szExeFile, L"peid.exe"))
		{
			printf("///////\nWARNING\n///////\n");
			exit(0);
		}
		if (!wcscmp(pe32.szExeFile, L"ida.exe"))
		{
			printf("///////\nWARNING\n///////\n");
			exit(0);
		}
		if (!wcscmp(pe32.szExeFile, L"idaq.exe"))
		{
			printf("///////\nWARNING\n///////\n");
			exit(0);
		}
		bMore = Process32Next(hProcessSnap, &pe32); // 获取下一个进程的句柄
	}
	CloseHandle(hProcessSnap);
}
void Debugger(void) {
	int result = 0;
	__asm {
		mov eax, dword ptr fs:[30h]//TEB偏移30H处
		movzx eax, byte ptr ds:[eax + 2h]//取PEB中BeingDebug，若为1则被调试
		mov result, eax
	}
	if (result) {
		printf("///////\nWARNING\n///////\n");
		exit(0);
	}
}
void NTAPI tls_callback(PVOID h, DWORD reason, PVOID pv)
{
	lookupprocess();
	Debugger();
	//MessageBox(NULL, L"Not Main!", L"Test1", MB_OK);
	printf("///////\nWARNING\n///////\n");
	return;
}
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback[] = { tls_callback, 0 };
#pragma data_seg()

///////////////////////////////////////////////////////////////////////////////////////

char user_name[256];
WORD enc_username[256];
char input_code[128];
unsigned char enc_t0[128];
unsigned char enc_t1[128];
unsigned char enc_t2[128];
unsigned char enc_t3[128];
BYTE * encf1_addr;
int encf1_size;
BYTE * encf2_addr;
int encf2_size;
BYTE * encf3_addr;
int encf3_size;
unsigned char enc_flag[] = { 0x1e, 0x15, 0x2, 0x10, 0xd, 0x48, 0x48, 0x6f, 0xdd, 0xdd, 0x48, 0x64, 0x63, 0xd7, 0x2e, 0x2c, 0xfe, 0x6a, 0x6d, 0x2a, 0xf2, 0x6f, 0x9a, 0x4d, 0x8b, 0x4b, 0x1e, 0x1e, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xb };

void fsuc_msg1() {
	MessageBoxA(NULL, "> CONFIRMED\n    SUCCESS", "WILLE", NULL);
}
void fsuc_msg2() {
	MessageBoxA(NULL, "> DETONATION FUNCTION\n    READY", "WILLE", NULL);
}
void fail_msg1() {
	MessageBoxA(NULL, "> BIOMETRIC VERIFICAION\n    FAILED", "WILLE", NULL);
}
void fail_msg2() {
	MessageBoxA(NULL, "> DSS Chock Connectivity\n    OUT OF RANGE", "WILLE", NULL);
}
void sub_msg() {
	MessageBoxA(NULL, "YOU CAN REDO.", "3.33", NULL);
}
void sub2_msg() {
	MessageBoxA(NULL, "YOU CAN (NOT) REDO.", "3.33", NULL);
}

BOOL Check_user() {
	int len = strlen(user_name);
	WORD check[] = { 0xa4, 0xa9, 0xaa, 0xbe, 0xbc, 0xb9, 0xb3, 0xa9, 0xbe, 0xd8, 0xbe};
	for (int i = 0; i < len/2; i++) {
		user_name[i] ^= user_name[len - 1 - i];
		user_name[len - 1 - i] ^= user_name[i];
		user_name[i] ^= user_name[len - 1 - i];
	}
	for (int i = 0; i < len; i++) {
		enc_username[i] = (user_name[i] ^(( (i ^ 0x76) + 0xcc) ^ 0x80) + 0x2B) & 0xFF;
	}
	for (int i = 0; i < len; i++) {
		//printf("%d %x\n", i, enc_username[i]);
		if (enc_username[i] != check[i]) {
			return 0;
		}
		else
			continue;
	}
	return 1;
}

BOOL GetSmcFuncAddrSize(BYTE * addr1, BYTE * addr2, BYTE * addr, int size) {
	int jmpdiff1 = 0;
	int jmpdiff2 = 0;

	if (*((unsigned char*)addr1) == 0xE9) {
		addr1++;
		jmpdiff1 = *(int *)addr1;
		addr1 += (jmpdiff1 + 4);
	}
	if (*((unsigned char*)addr2) == 0xE9) {
		addr2++;
		jmpdiff1 = *(int *)addr2;
		addr2 += (jmpdiff1 + 4);
	}
	addr = addr1;
	size = addr2 - addr;
	return TRUE;
}

BOOL  check_flag(unsigned char * enc_t, unsigned char * enc_flag) {
	for (int i = 0; i <35; i++) {
		if (enc_t[i] != enc_flag[i])
			return FALSE;
		else
			continue;
	}
	return TRUE;
}

int main(void) {
	HMODULE hImageBase = ::GetModuleHandle(NULL);
	printf("Welcome to HCTF 2017\n\n");
	printf("Mark.09 is hijacking Shinji Ikari now...\n\n");
	printf("Check User: \n");
	scanf_s("%s", user_name, 256);
	if (Check_user()) {
		fsuc_msg1();
	}
	else {
		fail_msg1();
		exit(0);
	}
	printf("Check Start Code: \n");
	scanf_s("%s", input_code, 128);
	while (getchar() != '\n') continue;
	if (strlen(input_code) != 35) {
		fail_msg2();
		sub_msg();
		exit(0);
	}
	enc0_f(enc_t0, input_code);
	GetSmcFuncAddrSize((BYTE *)enc3_f, (BYTE *)enc3_end, encf3_addr, encf3_size);
	if (!StaAD_NtQIP(1)) {
		bool bFind = GetSmcFuncAddrSize((BYTE *)enc1_f, (BYTE *)enc1_end, encf1_addr, encf1_size);
		//DecryptBlock(encf1_addr, encf1_size, 0xCC);
		enc1_f(enc_t1, enc_t0);
		EncryptBlock(encf1_addr, encf1_size, 0xCC);
	}
	else {
		fail_msg2();
		sub_msg();
		exit(0);
	}
	if (!StaAD_NtQIP(2)) {
		bool bFind = GetSmcFuncAddrSize((BYTE *)enc2_f, (BYTE *)enc2_end, encf2_addr, encf2_size);
		//DecryptBlock(encf2_addr, encf2_size, 0xCD);
		enc2_f(enc_t2, enc_t0);
		EncryptBlock(encf2_addr, encf2_size, 0xCD);
	}
	else {
		fail_msg2();
		sub_msg();
		exit(0);
	}
	if (!StaAD_NtQIP(3)) {
		bool bFind = GetSmcFuncAddrSize((BYTE *)enc3_f, (BYTE *)enc3_end, encf3_addr, encf3_size);
		//DecryptBlock(encf3_addr, encf3_size, 0xDD);
		enc3_f(enc_t3, enc_t0);
		EncryptBlock(encf3_addr, encf3_size, 0xDD);
	}
	else {
		fail_msg2();
		sub_msg();
		exit(0);
	}
	for (int i = 0; i < 7; i++) {
		enc_t0[7 + i] = enc_t1[i];
		enc_t0[14 + i] = enc_t2[i];
		enc_t0[21 + i] = enc_t3[i];
	}
	if (check_flag(enc_t0, enc_flag)) {
		MessageBoxA(NULL, "> DETONATION FUNCTION\n    READY", "WILLE", NULL);
		printf("[Y/N]?\n");
		char ynchr;
		scanf_s("%c", &ynchr, 1);
		if (ynchr == 'Y' || ynchr == 'y') {
			sub2_msg();
			printf("Prevent IMPACT success\n");
		}
		else {
			fail_msg2();
			sub_msg();
		}
	}
	else {
		fail_msg2();
		sub_msg();
	}
	
	system("pause");
	return 0;
}