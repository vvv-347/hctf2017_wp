#include "scode1.h"

void enc1_f(unsigned char * enc_t, unsigned char *plain_t) {
	for (int i = 0; i < 7; i++) {
		enc_t[i] = plain_t[7 + i] ^ 0xAD;
		int v1 = (enc_t[i] & 0xAA) >> 1;
		int v2 = (enc_t[i] << 1) & 0xAA;
		enc_t[i] = v1 | v2;
	}

}

void enc1_end() {
	printf("...");
}