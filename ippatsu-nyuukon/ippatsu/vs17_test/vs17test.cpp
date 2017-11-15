#include "stdafx.h"

#define CWK_DEV_SYM L"\\\\.\\slbkcdo_76d3d4d7"

// 从应用层给驱动发送一个字符串。
#define  CWK_DVC_SEND_STR \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x911,METHOD_BUFFERED, \
	FILE_WRITE_DATA)

// 从驱动读取一个字符串
#define  CWK_DVC_RECV_STR \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x912,METHOD_BUFFERED, \
	FILE_READ_DATA)

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE device = NULL;
	ULONG ret_len;
	int ret = 0;
	char tst_msg[1024] = { 0 };
	char * username;
	char * keygen;
	username = (char *)malloc(128 * sizeof(char));
	keygen = (char *)malloc(256 * sizeof(char));


	printf("<--- Let's Touch Fish --->\n\n");
	printf("Input username: ");
	scanf_s("%s", username, 128);
	if (strcmp(username, "Mr.Vuin")) {
		printf("U R Not Mo-Ing\n\n");
		return -1;
	}
	else
	{
		printf("Welcome, %s\n\n", username);
	}
	printf("Input keygen to check: ");
	scanf_s("%s", keygen, 128);

	device = CreateFile(CWK_DEV_SYM, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if (device == INVALID_HANDLE_VALUE)
	{
		printf("Open device failed.\n\n");
		return -1;
	}
	else
		printf("Open device successfully.\n\n");

	do {
		// 向驱动层SEND字符串
		if (!DeviceIoControl(device, CWK_DVC_SEND_STR, keygen, 256, NULL, 0, &ret_len, 0))
		{
			printf("SEND FAILED\n\n");
			ret = -5;
			break;
		}
		else
		{
			printf("SEND SUCCESS\n\n");
		}

		// 由驱动层RECV字符串
		if (!DeviceIoControl(device, CWK_DVC_RECV_STR, NULL, 0, tst_msg, 1024, &ret_len, 0))
		{
			printf("RECV FAILED\n\n");
			ret = -6;
			break;
		}
		else
		{
			printf("RECV SUCCESS\n\n");
		}

	} while (0);
	CloseHandle(device);
	return ret;
}

