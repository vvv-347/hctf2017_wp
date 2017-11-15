///
/// @file   coworker_sys.c
/// @author tanwen
/// @date   2012-5-28
///

#include <ntifs.h>
#include <wdmsec.h>

#define maxn 0x8000     // 理论支持明文长度    
#define ENCODE 0,16,1       // 加密用的宏    


PDEVICE_OBJECT g_cdo = NULL;
LARGE_INTEGER tick_count;
ULONG randnum;
char randchr;
unsigned char encflag[] = "aed3899df15bd7babb99acf5ebb9f5cd8cd44a77c53263de46ef9f3d773fe908";
char input_s[1024] = { 0, };
char input_enc[1024] = { 0, };
unsigned char input_rand[1024] = { 0, };
int basecount = 0;

const GUID  CWK_GUID_CLASS_MYCDO =
{ 0x17d1a0e0L, 0x3249, 0x12e1,{ 0x92,0x16, 0x45, 0x21, 0xa1, 0x30, 0x29, 0x06 } };

#define CWK_CDO_SYB_NAME    L"\\??\\slbkcdo_76d3d4d7"

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

// 定义一个链表用来保存字符串
#define CWK_STR_LEN_MAX 512
typedef struct {
	LIST_ENTRY list_entry;
	char buf[CWK_STR_LEN_MAX];
} CWK_STR_NODE;

// 还必须有一把自旋锁来保证链表操作的安全性
KSPIN_LOCK g_cwk_lock;
// 一个事件来标识是否有字符串可以取
KEVENT  g_cwk_event;
// 必须有个链表头
LIST_ENTRY g_cwk_str_list;

#define MEM_TAG 'cwkr'


char msg[maxn];
char res[32];
char msgb[72], msgbt[72], keyb[18][72];
char key[16] = "deadbeef";

// 明文初始置换    
char msg_ch[64] = {
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

// 密钥初始置换    
char key_ch[56] = {
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

// 扩展置换    
char msg_ex[48] = {
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

// 每轮密钥的位移    
char key_mov[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

// 压缩置换    
char key_cmprs[48] = {
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

// S 盒置换    
char s_box[8][4][16] = {
	// S1    
	14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
	// S2    
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
	// S3    
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
	// S4    
	7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
	3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
	// S5    
	2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
	// S6    
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
	// S7    
	4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
	// S8    
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};

// P 盒置换    
char p_box[32] = {
	16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
	2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25
};

// 末置换    
char last_ch[64] = {
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};

// hash 置换，将加密后的密文置换为可读明文    
char hs_ch[20] = "0123456789abcdef";
char sh_ch[128];

void init_trans() {
	char i;
	for (i = 0; i < 16; i++)
		sh_ch[hs_ch[i]] = i;    // 完成hash转换的对应    
}


// 字符转成二进制    
void ChToBit(char* dest, char* src, int length) {
	int i, j;
	char t;
	for (i = 0; i < length; i++) {
		for (j = 8, t = src[i]; j > 0; j--) {
			dest[(i << 3) + j] = t & 1;   // 取字符末位    
			t >>= 1;
		}
	}
}

// 二进制转成字符    
void BitToCh(char* dest, char* src, int length) {
	int i;
	for (i = 0; i < length << 3; i++) {
		dest[i >> 3] <<= 1;
		dest[i >> 3] |= src[i + 1];   // 添加到末位    
	}
	dest[length] = 0;
}

// 批置换，以offset为偏移，以count为长度    
void BatchSet(char* dest, char* src, char* offset, int count) {
	int i;
	for (i = 0; i < count; i++)
		dest[i + 1] = src[offset[i]];
}

// 得到16轮所需的密钥    
void getKeys() {
	char tk[128], bk[72];
	char* ptk = tk;
	int i, j;
	for (i = 0; i < 8; i++)
		key[i] <<= 1; // 跳过奇偶校验位    
	ChToBit(bk, key, 8);
	BatchSet(tk, bk, key_ch, 56);
	for (i = 0; i < 16; i++) {
		for (j = 0; j < key_mov[i]; j++, ptk++) {
			ptk[57] = ptk[28];
			ptk[28] = ptk[1];
			// ptk++ 为亮点所在，实质上每一位都没有左移，只是指针右移了    
		}
		BatchSet(keyb[i], ptk, key_cmprs, 48);
	}
}

// 将加密后的密文转换为可读的明文    
void msgPro(char* dest, char* src) {
	int i, j;
	for (i = 0; i < 16; i++) {
		dest[i] = 0;
		for (j = 1; j <= 4; j++) // 取4位按hash构造一个字符    
			dest[i] = (dest[i] << 1) | src[i * 4 + j];
		dest[i] = hs_ch[dest[i]];
	}
	dest[i] = 0;
}

// 通用加/解密函数，后面三个参数由宏ENCODE和DECODE提供    
void DES(char* pmsg, int st, int cl, int step) {
	int i, row, col;
	char r[64], rt[48], s[8];
	ChToBit(msgbt, pmsg, 8);
	BatchSet(msgb, msgbt, msg_ch, 64); // 初始置换    
	for (; st != cl; st += step) {
		memcpy(rt, msgb + 33, 32);
		BatchSet(r, msgb + 32, msg_ex, 48); // 扩展置换    
		for (i = 1; i <= 48; i++)
			r[i] ^= keyb[st][i]; // 异或操作    
								 // s_box 代替    
		for (i = 0; i < 48; i += 6) {
			row = col = 0;
			row = r[i + 1] << 1 | r[i + 6];
			col = (r[i + 2] << 3) | (r[i + 3] << 2) | (r[i + 4] << 1) | r[i + 5];
			s[i / 12] = (s[i / 12] <<= 4) | s_box[i / 6][row][col];
		}
		ChToBit(r, s, 4);
		BatchSet(msgb + 32, r, p_box, 32); // p_box 置换    
		for (i = 1; i <= 32; i++)
			msgb[i + 32] ^= msgb[i]; // 异或    
		memcpy(msgb + 1, rt, 32);
	}
	memcpy(msgbt + 33, msgb + 1, 32);
	memcpy(msgbt + 1, msgb + 33, 32);
	BatchSet(msgb, msgbt, last_ch, 64); // 末置换    
	msgPro(res, msgb); // 使密文可读   
}



// 分配内存并初始化一个链表节点
CWK_STR_NODE *cwkMallocStrNode()
{
	CWK_STR_NODE *ret = ExAllocatePoolWithTag(
		NonPagedPool, sizeof(CWK_STR_NODE), MEM_TAG);
	if (ret == NULL)
		return NULL;
	return ret;
}

void cwkUnload(PDRIVER_OBJECT driver)
{
	UNICODE_STRING cdo_syb = RTL_CONSTANT_STRING(CWK_CDO_SYB_NAME);
	CWK_STR_NODE *str_node;
	ASSERT(g_cdo != NULL);
	IoDeleteSymbolicLink(&cdo_syb);
	IoDeleteDevice(g_cdo);

	// 负责的编程态度：释放分配过的所有内核内存。
	while (TRUE)
	{
		str_node = (CWK_STR_NODE *)ExInterlockedRemoveHeadList(
			&g_cwk_str_list, &g_cwk_lock);
		// str_node = RemoveHeadList(&g_cwk_str_list);
		if (str_node != NULL)
			ExFreePool(str_node);
		else
			break;
	};
}

NTSTATUS cwkDispatch(
	IN PDEVICE_OBJECT dev,
	IN PIRP irp)
{
	PIO_STACK_LOCATION  irpsp = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ret_len = 0;
	ULONG seed = 0x76;
	while (dev==g_cdo)
	{
		// 如果这个请求不是发给g_cdo的，那就非常奇怪了。
		// 因为这个驱动只生成过这一个设备。所以可以直接
		// 返回失败。
		if (irpsp->MajorFunction == IRP_MJ_CREATE || irpsp->MajorFunction == IRP_MJ_CLOSE)
		{
			// 生成和关闭请求，这个一律简单地返回成功就可以
			// 了。就是无论何时打开和关闭都可以成功。
			break;
		}

		if (irpsp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
		{
			RtlRandomEx(&seed);
			// 处理DeviceIoControl。
			PVOID buffer = irp->AssociatedIrp.SystemBuffer;
			ULONG inlen = irpsp->Parameters.DeviceIoControl.InputBufferLength;
			ULONG outlen = irpsp->Parameters.DeviceIoControl.OutputBufferLength;
			ULONG len;
			CWK_STR_NODE *str_node; // 初始化链表头
			switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
			{
			case CWK_DVC_SEND_STR:

				ASSERT(buffer != NULL);
				ASSERT(outlen == 0);

				if (inlen > CWK_STR_LEN_MAX)
				{
					status = STATUS_INVALID_PARAMETER;
					break;
				}

				DbgPrint("SEND: ");
				DbgPrint((char *)buffer);
				//DbgPrint("strlen: %d", strlen(buffer));
				if (strnlen((char *)buffer, inlen) == inlen)
				{
					// 字符串占满了缓冲区，且中间没有结束符。立刻返回错误。
					status = STATUS_INVALID_PARAMETER;
					break;
				}

				// 现在可以认为输入缓冲是安全而且不含恶意的。分配节点。
				str_node = cwkMallocStrNode();
				if (str_node == NULL)
				{
					// 如果分配不到空间了，返回资源不足的错误
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				// 至此检查字符串正常 可以进行加密操作				
				RtlCopyMemory(msg, (char*)buffer, strlen(buffer) + 1);

				//DbgPrint((char*)msg);
				//DbgPrint("lenthmsg: %d", strlen(msg));
				init_trans();
				getKeys();
				for (int i = 0; msg[i]; i += 8) {
					DES(msg + i, ENCODE);
					
					for (int j = 0; j < 16; j++) {
						input_enc[basecount + j] = res[j];
					}
					
					//DbgPrint((char*)res);
					basecount += 16;
				}
				//DbgPrint((char *)input_enc);

				// 加密操作完成 讲加密后的数据添加到链表
				strncpy(str_node->buf, (char *)input_enc, CWK_STR_LEN_MAX);
				ExInterlockedInsertTailList(&g_cwk_str_list, (PLIST_ENTRY)str_node, &g_cwk_lock);
				KeSetEvent(&g_cwk_event, 0, FALSE);
				randnum = RtlRandomEx(&(tick_count.LowPart));
				randchr = randnum % 0xFF;
				basecount = 0;
				break;

			case CWK_DVC_RECV_STR:
				ASSERT(buffer != NULL);
				ASSERT(inlen == 0);
				// 应用要求接收字符串。对此，安全上要求是输出缓冲要足够长。
				if (outlen < CWK_STR_LEN_MAX)
				{
					status = STATUS_INVALID_PARAMETER;
					break;
				}
				while (1)
				{
					// 从链表中取出首节点
					str_node = (CWK_STR_NODE *)ExInterlockedRemoveHeadList(&g_cwk_str_list, &g_cwk_lock);
					if (str_node != NULL)
					{
						DbgPrint("RECV: ");
						memset(input_rand, 0, 1024);
						strncpy(input_rand, str_node->buf, CWK_STR_LEN_MAX);
						//DbgPrint("%s", input_rand);
						ret_len = strnlen(str_node->buf, CWK_STR_LEN_MAX) + 1;
						for (int i = 0; i < strlen(input_rand); i++) {
							input_rand[i] ^= randchr;
							DbgPrint("%x", input_rand[i]);
						}
						for (int i = 0; i < strlen(encflag); i++) {
							encflag[i] ^= randchr;
							//DbgPrint("%x", input_rand[i]);
						}
						if (!strcmp(encflag, input_rand)) {
							DbgPrint("Success");
						}
						else
							DbgPrint("FAILED");
						ExFreePool(str_node);
						randnum = RtlRandomEx(&(tick_count.LowPart));
						randchr = randnum % 0xFF;
						break;
					}
					else
					{
						KeWaitForSingleObject(&g_cwk_event, Executive, KernelMode, 0, 0);
					}
				}
				break;
			default:
				// 到这里的请求都是不接受的请求。未知的请求一律返回非法参数错误。
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		break;
	}
	// 返回结果
	irp->IoStatus.Information = ret_len;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
	NTSTATUS status;
	ULONG i;
	UCHAR mem[256] = { 0 };

	// 生成一个控制设备。然后生成符号链接。
	UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;WD)");
	UNICODE_STRING cdo_name = RTL_CONSTANT_STRING(L"\\Device\\cwk_3948d33e");
	UNICODE_STRING cdo_syb = RTL_CONSTANT_STRING(CWK_CDO_SYB_NAME);

	//KdBreakPoint();

	// 生成一个控制设备对象。
	status = IoCreateDeviceSecure(
		driver,
		0, &cdo_name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE, &sddl,
		(LPCGUID)&CWK_GUID_CLASS_MYCDO,
		&g_cdo);
	if (!NT_SUCCESS(status))
		return status;

	// 生成符号链接.
	IoDeleteSymbolicLink(&cdo_syb);
	status = IoCreateSymbolicLink(&cdo_syb, &cdo_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(g_cdo);
		return status;
	}

	// 初始化事件、锁、链表头。
	KeInitializeEvent(&g_cwk_event, SynchronizationEvent, TRUE);
	KeInitializeSpinLock(&g_cwk_lock);
	InitializeListHead(&g_cwk_str_list);

	
	KeQueryTickCount(&tick_count);
	randnum = RtlRandomEx(&(tick_count.LowPart));
	randchr = randnum % 0xFF;
	//DbgPrint("rand: %c", randchr);

	// 所有的分发函数都设置成一样的。
	for (i = 0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		driver->MajorFunction[i] = cwkDispatch;
	}

	// 支持动态卸载。
	driver->DriverUnload = cwkUnload;
	// 清除控制设备的初始化标记。
	g_cdo->Flags &= ~DO_DEVICE_INITIALIZING;
	return STATUS_SUCCESS;
}
