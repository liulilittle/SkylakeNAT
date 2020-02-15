#pragma once

#include <stdio.h>

void rc4_crypt(unsigned char* key, int keylen, unsigned char* data, int datalen, int subtract, int E);