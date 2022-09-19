#pragma once

#include <string.h>
#include <stddef.h>
#include <stdint.h>

size_t base64url_decode(unsigned char *bufplain, const unsigned char *bufcoded);
size_t base64url_encode(unsigned char *encoded, const unsigned char *string, int len);
