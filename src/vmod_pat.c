#include "config.h"

#include <stdlib.h>
#include <cache/cache.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <openssl/x509.h>


#include "vend.h" // For some reason not shared
#include "vqueue.h"

#include "vcc_pat_if.h"
#include "base64_url.h"

#define TOKEN_SIZE 354
#define AUTHINPUT_SIZE 98

struct vmod_pat_pat
{
	unsigned magic;
#define VMOD_PAT_MAGIC 0xaed11337
	struct vsc_seg *vsc_seg;
	char *basic_key;
	size_t basic_key_length;
	char *issuer;
	int max_age;
};

struct token
{
	uint16_t token_type;
	uint8_t nonce[32];
	uint8_t context[32];
	uint8_t key_id[32];
	uint8_t authenticator[256];
};

int token_authenticatorinput(struct token *t, char *buff, size_t l)
{
	/*
		This function is used to compare checksum for the RSA validation
	*/

	if (l != AUTHINPUT_SIZE)
		return -1;

	char *p = buff;

	vbe16enc(p, t->token_type);
	p += 2;

	// Client generated nonce
	memcpy(p, t->nonce, 32);
	p += 32;

	memcpy(p, t->context, 32);
	p += 32;
	memcpy(p, t->key_id, 32);

	return 0;
}

int token_unmarchal(struct token *t, const char *d, size_t l)
{
	if (l != TOKEN_SIZE)
		return -1;

	const char *p = d;

	t->token_type = vbe16dec(p);
	p += 2;

	// Client generated nonce
	memcpy(t->nonce, p, 32);
	p += 32;
	memcpy(t->context, p, 32);
	p += 32;
	memcpy(t->key_id, p, 32);
	p += 32;
	memcpy(t->authenticator, p, 256);

	return 0;
}

size_t tokenchallenge_marchal(uint16_t token_type, const char *issuer, const char *nonce, size_t nonce_length, const char *originfo, char *buf, int buflen)
{
	AN(issuer);
	AN(originfo);

	int issuer_length, originfo_length;
	char *p;

	issuer_length = strlen(issuer);
	originfo_length = strlen(originfo);

	if (buflen < 2 + 2 + issuer_length + 1 + nonce_length + 2 + originfo_length)
		return -1;

	p = buf;

	vbe16enc(p, token_type);
	p += 2;

	vbe16enc(p, issuer_length);
	p += 2;

	memcpy(p, issuer, issuer_length);
	p += issuer_length;

	if (nonce_length)
	{
		*p = nonce_length;
		p++;

		memcpy(p, nonce, nonce_length);
		p += nonce_length;
	}
	else
	{
		*p = 0;
		p++;
	}

	vbe16enc(p, originfo_length);
	p += 2;

	memcpy(p, originfo, originfo_length);
	p += originfo_length;

	return p - buf;
}

int hash_nonce(const char *nonce, char *buf)
{
	SHA256_CTX c;
	SHA256_Init(&c);
	SHA256_Update(&c, nonce, strlen(nonce));
	SHA256_Final(buf, &c);

	return 0;
}

bool token_verify(struct token *t, const unsigned char *key, int keyLength)
{
	// temp buffer
	unsigned char buffer[256];
	char auth_input[AUTHINPUT_SIZE] = {0};

	if (token_authenticatorinput(t, auth_input, sizeof(auth_input)) != 0)
		return false;

	unsigned char hashed[48] = {0};
	SHA512_CTX c;
	SHA384_Init(&c);
	SHA384_Update(&c, auth_input, sizeof(auth_input));
	SHA384_Final(hashed, &c);

	RSA *rsa = d2i_RSA_PUBKEY(NULL, &key, keyLength);

	RSA_public_decrypt(256, t->authenticator, buffer, rsa, RSA_NO_PADDING);

	return RSA_verify_PKCS1_PSS(rsa, hashed, EVP_sha384(), buffer, 48) == 1;
}

VCL_VOID v_matchproto_()
	vmod_pat__init(VRT_CTX, struct vmod_pat_pat **patp, const char *vcl_name, struct arg_vmod_pat_pat__init *opt)
{
	char buff[1024];

	struct vmod_pat_pat *pat;
	int key_length;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(patp);
	AZ(*patp);
	AN(vcl_name);
	ALLOC_OBJ(pat, VMOD_PAT_MAGIC);
	AN(pat);

	key_length = strlen(opt->public_key);

	pat->basic_key_length = base64url_decode(buff, (unsigned char *)opt->public_key);
	pat->basic_key = malloc(sizeof(char) * pat->basic_key_length);
	memcpy(pat->basic_key, buff, pat->basic_key_length);

	pat->issuer = strdup(opt->issuer);
	pat->max_age = opt->max_age;

	*patp = pat;

	return;
}

VCL_VOID v_matchproto_()
	vmod_pat__fini(struct vmod_pat_pat **patp)
{
	struct vmod_pat_pat *pat;

	free(pat->basic_key);
	free(pat->issuer);

	pat->basic_key = NULL;
	pat->issuer = NULL;

	AN(*patp);
	pat = *patp;
	*patp = NULL;
	CHECK_OBJ_NOTNULL(pat, VMOD_PAT_MAGIC);
	FREE_OBJ(pat);
}

bool compare_challenges(char *a, size_t a_l, char *b)
{
	char buf[32] = {0};

	SHA256_CTX c;
	SHA256_Init(&c);
	SHA256_Update(&c, a, a_l);
	SHA256_Final(buf, &c);

	if (memcmp(buf, b, 32) == 0)
		return true;

	return false;
}

VCL_BOOL v_matchproto_()
	vmod_pat_validate_header(VRT_CTX, struct vmod_pat_pat *pat, struct arg_vmod_pat_pat_validate_header *opt)
{
	const char *p;
	struct token t;
	int hdr_l;
	size_t l;
	char hash[32] = {0};

	p = opt->hdr;

	char buf[AUTHINPUT_SIZE];
	char token_challenge_buf[1000];
	char base64_dec[1000 * 4];

	if (pat->issuer == NULL || opt->origin == NULL)
		return false;

	if (opt->hdr == NULL)
		return false;

	if (strlen(opt->hdr) > 1000)
		return false;

	if (strncmp("PrivateToken", p, 12))
		return false;

	p += 12;

	while (isspace(*p))
		p++;

	if (strncmp("token=", p, 6))
		return false;

	p += 6;

	l = base64url_decode(base64_dec, p);

	if (token_unmarchal(&t, base64_dec, l) != 0)
		return false;

	if (t.token_type != 0x02)
		return false;

	if (!token_verify(&t, pat->basic_key, pat->basic_key_length))
		return false;

	if (opt->nonce != NULL)
		hash_nonce(opt->nonce, hash);

	l = tokenchallenge_marchal(2, pat->issuer, hash, opt->nonce != NULL ? 32 : 0, opt->origin, token_challenge_buf, 1000);

	return compare_challenges(token_challenge_buf, l, t.context);
}
VCL_STRING v_matchproto_()
	vmod_pat_generate_token_header(VRT_CTX, struct vmod_pat_pat *pat, struct arg_vmod_pat_pat_generate_token_header *opt)
{
	char buf[1000];
	char buf2[1000];
	char hash[32] = {0};
	char token_challenge_buf[1000];

	char *p;
	unsigned u, v;
	size_t l;

	if (pat->issuer == NULL || opt->origin == NULL)
		return "";

	if (opt->nonce != NULL)
		hash_nonce(opt->nonce, hash);

	l = tokenchallenge_marchal(2, pat->issuer, hash, opt->nonce != NULL ? 32 : 0, opt->origin, token_challenge_buf, 1000);

	base64url_encode(buf, pat->basic_key, pat->basic_key_length);
	base64url_encode(buf2, token_challenge_buf, l);

	u = WS_ReserveAll(ctx->ws); /* Reserve some work space */
	p = ctx->ws->f;				/* Front of workspace area */
	v = snprintf(p, u, "PrivateToken challenge=%s, token-key=%s, max_age=%i", buf2, buf, pat->max_age);
	v++;
	if (v > u)
	{
		/* No space, reset and leave */
		WS_Release(ctx->ws, 0);
		return (NULL);
	}
	/* Update work space with what we've used */
	WS_Release(ctx->ws, v);
	return (p);
}