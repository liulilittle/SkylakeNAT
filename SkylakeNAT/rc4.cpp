#include "rc4.h"

static void
rc4_sbox(unsigned char* box, unsigned char* key, int keylen) {
    if (NULL == box || NULL == key || keylen <= 0)
        return;

    for (int i = 0; i < 255; i++)
        box[i] = (unsigned char)i;

    for (int i = 0, j = 0; i < 255; i++) {
        j = (j + box[i] + key[i % keylen]) % 255;
        unsigned char b = box[i];
        box[i] = box[j];
        box[j] = b;
    }
}

void
rc4_crypt(unsigned char* key, int keylen, unsigned char* data, int datalen, int subtract, int E) {
    if (NULL == key || keylen <= 0 || NULL == data || datalen <= 0)
        return;

    unsigned char box[255];
    rc4_sbox(box, key, keylen);

	unsigned char x = (unsigned char)(E ? subtract : -subtract);
	for (int i = 0, low = 0, high = 0, mid; i < datalen; i++) {
		low = low % 255;
		high = (high + box[i % 255]) % 255;

		unsigned char b = box[low];
		box[low] = box[high];
		box[high] = b;

		mid = (box[low] + box[high]) % 255;
		if (E)
			data[i] = (unsigned char)((data[i] ^ box[mid]) - x);
		else
			data[i] = (unsigned char)((data[i] - x) ^ box[mid]);
	}
}