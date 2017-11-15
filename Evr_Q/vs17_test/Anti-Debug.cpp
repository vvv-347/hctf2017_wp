#include "Anti-Debug.h"

int StaAD_NtQIP(int type) {
	typedef NTSTATUS(WINAPI *NTQUERYINFORMATIONPROCESS)(
		HANDLE ProcessHandle,
		saohua ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength
		);

	NTQUERYINFORMATIONPROCESS pNtQueryInformationProcess = NULL;

	pNtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"),
			"NtQueryInformationProcess");

	if (type == 1) {
		DWORD dwDebugPort = 0;
		pNtQueryInformationProcess(GetCurrentProcess(),
			wuyazuoweiji,
			&dwDebugPort,
			sizeof(dwDebugPort),
			NULL);
		if (dwDebugPort != 0x0)
			return 1;
		else
			return 0;
	}
	else if (type == 2) {
		HANDLE hDebugObject = NULL;
		pNtQueryInformationProcess(GetCurrentProcess(),
			zhizhuchiershi,
			&hDebugObject,
			sizeof(hDebugObject),
			NULL);
		if (hDebugObject != 0x0)
			return 1;
		else
			return 0;
	}
	else if (type == 3) {
		BOOL bDebugFlag = TRUE;
		pNtQueryInformationProcess(GetCurrentProcess(),
			longjuanfengcuihuipark,
			&bDebugFlag,
			sizeof(bDebugFlag),
			NULL);
		if (bDebugFlag == 0x0)
			return 1;
		else
			return 0;
	}
	else
		return 1;
}