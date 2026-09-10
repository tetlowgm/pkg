/*-
 * SPDX-License-Identifier: LicenseRef-scancode-bsd-unchanged
 *
 * Copyright (c) 2011-2013 Baptiste Daroussin <bapt@FreeBSD.org>
 * Copyright (c) 2011-2012 Julien Laffaye <jlaffaye@FreeBSD.org>
 * Copyright (c) 2026 Gordon Tetlow <gordon@FreeBSD.org>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/stat.h>
#include <sys/param.h>

#include <fcntl.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "pkg.h"
#include "private/event.h"
#include "private/pkg.h"
#include "private/pkgsign.h"

#if OPENSSL_VERSION_NUMBER >= 0x30500000L

struct mldsa_sign_ctx {
	struct pkgsign_ctx sctx;
	EVP_PKEY *key;
};

/* Grab the mldsa context from a pkgsign_ctx. */
#define	MLDSA_CTX(c)	((struct mldsa_sign_ctx *)(c))

static int
_load_private_key(struct mldsa_sign_ctx *keyinfo)
{
	FILE *fp;

	if ((fp = fopen(keyinfo->sctx.path, "re")) == NULL)
		return (EPKG_FATAL);

	keyinfo->key = PEM_read_PrivateKey(fp, 0, keyinfo->sctx.pw_cb,
	    keyinfo->sctx.path);
	if (keyinfo->key == NULL) {
		fclose(fp);
		return (EPKG_FATAL);
	}

	fclose(fp);
	return (EPKG_OK);
}

static EVP_PKEY *
_load_public_key_buf(unsigned char *cert, int certlen)
{
	EVP_PKEY *pkey;
	BIO *bp;
	char errbuf[1024];

	bp = BIO_new_mem_buf((void *)cert, certlen);
	if (bp == NULL) {
		pkg_emit_error("error allocating public key bio: %s",
		    ERR_error_string(ERR_get_error(), errbuf));
		return (NULL);
	}

	pkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
	if (pkey == NULL) {
		pkg_emit_error("error reading public key: %s",
		    ERR_error_string(ERR_get_error(), errbuf));
		BIO_free(bp);
		return (NULL);
	}

	BIO_free(bp);
	return (pkey);
}

struct mldsa_verify_cbdata {
	unsigned char *key;
	size_t keylen;
	unsigned char *sig;
	size_t siglen;
	bool verbose;
};

static int
mldsa_verify_cert_cb(int fd, void *ud)
{
	struct mldsa_verify_cbdata *cbdata = ud;
	char *sha512;
	char *hash;
	char errbuf[1024];
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx;
	int ret;

	sha512 = pkg_checksum_fd(fd, PKG_HASH_TYPE_SHA512_HEX);
	if (sha512 == NULL)
		return (EPKG_FATAL);

	hash = pkg_checksum_data(sha512, strlen(sha512),
	    PKG_HASH_TYPE_SHA512_RAW);
	free(sha512);

	pkey = _load_public_key_buf(cbdata->key, cbdata->keylen);
	if (pkey == NULL) {
		free(hash);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
		EVP_PKEY_free(pkey);
		free(hash);
		return (EPKG_FATAL);
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL) {
		EVP_PKEY_free(pkey);
		free(hash);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_verify_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		free(hash);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		free(hash);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha512()) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		free(hash);
		return (EPKG_FATAL);
	}

	ret = EVP_PKEY_verify(ctx, cbdata->sig, cbdata->siglen, hash,
	    pkg_checksum_type_size(PKG_HASH_TYPE_SHA512_RAW));
	free(hash);
	if (ret <= 0 && cbdata->verbose) {
		if (ret < 0)
			pkg_dbg(PKG_DBG_VERIFY, 1, "rsa verify failed: %s",
					ERR_error_string(ERR_get_error(), errbuf));
		pkg_emit_error("signature verification failure");
	}
	if (ret <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		return (EPKG_FATAL);
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	return (EPKG_OK);
}

static int
mldsa_verify_cert(const struct pkgsign_ctx *sctx __unused, unsigned char *key,
    size_t keylen, unsigned char *sig, size_t siglen, int fd)
{
	int ret;
	bool need_close = false;
	struct mldsa_verify_cbdata cbdata;

	(void)lseek(fd, 0, SEEK_SET);

	cbdata.key = key;
	cbdata.keylen = keylen;
	cbdata.sig = sig;
	cbdata.siglen = siglen;
	cbdata.verbose = true;

	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();

	ret = pkg_emit_sandbox_call(mldsa_verify_cert_cb, fd, &cbdata);
	if (need_close)
		close(fd);

	return (ret);
}

static int
mldsa_verify_cb(int fd, void *ud)
{
	struct mldsa_verify_cbdata *cbdata = ud;
	char *sha512;
	char errbuf[1024];
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx;
	int ret;

	sha512 = pkg_checksum_fd(fd, PKG_HASH_TYPE_SHA512_HEX);
	if (sha512 == NULL)
		return (EPKG_FATAL);

	pkey = _load_public_key_buf(cbdata->key, cbdata->keylen);
	if (pkey == NULL) {
		free(sha512);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
		EVP_PKEY_free(pkey);
		free(sha512);
		return (EPKG_FATAL);
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL) {
		EVP_PKEY_free(pkey);
		free(sha512);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_verify_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		free(sha512);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		free(sha512);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_md_pkg_sha1()) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		free(sha512);
		return (EPKG_FATAL);
	}

	ret = EVP_PKEY_verify(ctx, cbdata->sig, cbdata->siglen, sha512,
	    pkg_checksum_type_size(PKG_HASH_TYPE_SHA512_HEX));
	free(sha512);
	if (ret <= 0) {
		if (ret < 0)
			pkg_dbg(PKG_DBG_VERIFY, 1, "%s: %s", cbdata->key,
				ERR_error_string(ERR_get_error(), errbuf));
		pkg_emit_error("%s: signature verification failure",
		    cbdata->key);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		return (EPKG_FATAL);
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	return (EPKG_OK);
}

static int
mldsa_verify(const struct pkgsign_ctx *sctx __unused, const char *keypath,
    unsigned char *sig, size_t sig_len, int fd)
{
	int ret;
	bool need_close = false;
	struct mldsa_verify_cbdata cbdata;
	char *key_buf;
	off_t key_len;

	if (file_to_buffer(keypath, (char**)&key_buf, &key_len) != EPKG_OK) {
		pkg_emit_errno("mldsa_verify", "cannot read key");
		return (EPKG_FATAL);
	}

	(void)lseek(fd, 0, SEEK_SET);

	/*
	 * XXX Older versions of pkg write out the NUL terminator of the
	 * signature, so we shim it out here to avoid breaking compatibility.
	 * We can't do it at a lower level in the caller, because other signers
	 * may use a binary format that could legitimately contain a nul byte.
	 */
	if (sig[sig_len - 1] == '\0')
		sig_len--;

	cbdata.key = key_buf;
	cbdata.keylen = key_len;
	cbdata.sig = sig;
	cbdata.siglen = sig_len;
	cbdata.verbose = false;

	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();

	ret = pkg_emit_sandbox_call(mldsa_verify_cert_cb, fd, &cbdata);
	if (need_close)
		close(fd);
	if (ret != EPKG_OK) {
		cbdata.verbose = true;
		(void)lseek(fd, 0, SEEK_SET);
		ret = pkg_emit_sandbox_call(mldsa_verify_cb, fd, &cbdata);
	}

	free(key_buf);

	return (ret);
}

int
mldsa_sign_data(struct pkgsign_ctx *sctx, const unsigned char *msg, size_t msgsz,
    unsigned char **sigret, size_t *siglen)
{
	char errbuf[1024];
	struct mldsa_sign_ctx *keyinfo = MLDSA_CTX(sctx);
	int max_len = 0, ret;
	EVP_PKEY_CTX *ctx;
	const EVP_MD *md;

	md = EVP_sha512();
	char *hash;

	if (keyinfo->key == NULL && _load_private_key(keyinfo) != EPKG_OK) {
		pkg_emit_error("can't load key from %s", keyinfo->sctx.path);
		return (EPKG_FATAL);
	}

	max_len = EVP_PKEY_size(keyinfo->key);
	*sigret = xcalloc(1, max_len + 1);

	ctx = EVP_PKEY_CTX_new(keyinfo->key, NULL);
	if (ctx == NULL)
		return (EPKG_FATAL);

	if (EVP_PKEY_sign_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return (EPKG_FATAL);
	}

	*siglen = max_len;
	hash = pkg_checksum_data(msg, msgsz, PKG_HASH_TYPE_SHA512_RAW);
	ret = EVP_PKEY_sign(ctx, *sigret, siglen, hash,
	    EVP_MD_size(md));
	free(hash);

	if (ret <= 0) {
		pkg_dbg(PKG_DBG_VERIFY, 1, "%s: %s", keyinfo->sctx.path,
		   ERR_error_string(ERR_get_error(), errbuf));
		pkg_emit_error("%s: signing failed", keyinfo->sctx.path);
		EVP_PKEY_CTX_free(ctx);
		return (EPKG_FATAL);
	}

	assert(*siglen < INT_MAX);
	EVP_PKEY_CTX_free(ctx);
	*siglen += 1;
	return (EPKG_OK);
}

int
mldsa_sign(struct pkgsign_ctx *sctx, const char *path, unsigned char **sigret,
    size_t *siglen)
{
	struct mldsa_sign_ctx *keyinfo = MLDSA_CTX(sctx);
	char *sha512;
	int ret;

	if (access(keyinfo->sctx.path, R_OK) == -1) {
		pkg_emit_errno("access", keyinfo->sctx.path);
		return (EPKG_FATAL);
	}

	sha512 = pkg_checksum_file(path, PKG_HASH_TYPE_SHA512_HEX);
	if (sha512 == NULL)
		return (EPKG_FATAL);

	ret = mldsa_sign_data(sctx, sha512, strlen(sha512), sigret, siglen);

	free(sha512);

	return (ret);
}

static int
mldsa_generate(struct pkgsign_ctx *sctx, const struct iovec *iov __unused,
    int niov __unused)
{
	char errbuf[1024];
	struct mldsa_sign_ctx *keyinfo = MLDSA_CTX(sctx);
	const char *path = sctx->path;
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey;
	FILE *fp;
	int rc;

	if (niov != 0)
		return (EPKG_FATAL);

	fp = fopen(path, "w");
	if (fp == NULL) {
		pkg_emit_errno("fopen write", path);
		return (EPKG_FATAL);
	}

	if (fchmod(fileno(fp), 0400) != 0) {
		pkg_emit_errno("fchmod", path);
		fclose(fp);
		return (EPKG_FATAL);
	}

	pkey = NULL;
	rc = EPKG_FATAL;
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (ctx == NULL)
		goto out;

	if (EVP_PKEY_keygen_init(ctx) <= 0)
		goto out;

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
		goto out;

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		goto out;

	if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, 0, NULL) <= 0)
		goto out;

	rc = EPKG_OK;
	if (keyinfo->key != NULL)
		EVP_PKEY_free(keyinfo->key);
	keyinfo->key = pkey;
out:
	if (rc != EPKG_OK) {
		pkg_dbg(PKG_DBG_VERIFY, 1, "%s: %s", path,
		    ERR_error_string(ERR_get_error(), errbuf));
		pkg_emit_error("%s: error loading private key", path);

		/* keyinfo claims the pkey on success for any future operations. */
		EVP_PKEY_free(pkey);
	}

	fclose(fp);
	EVP_PKEY_CTX_free(ctx);
	return (rc);
}

static int
mldsa_pubkey(struct pkgsign_ctx *sctx, char **pubkey, size_t *pubkeylen)
{
	char errbuf[1024];
	struct mldsa_sign_ctx *keyinfo = MLDSA_CTX(sctx);
	BIO *bp;

	if (keyinfo->key == NULL && _load_private_key(keyinfo) != EPKG_OK) {
		pkg_emit_error("can't load key from %s", sctx->path);
		return (EPKG_FATAL);
	}

	bp = BIO_new(BIO_s_mem());
	if (bp == NULL) {
		pkg_emit_error("error allocating public key bio: %s",
		    ERR_error_string(ERR_get_error(), errbuf));
		return (EPKG_FATAL);
	}

	BIO_set_close(bp, BIO_NOCLOSE);

	if (PEM_write_bio_PUBKEY(bp, keyinfo->key) <= 0) {
		pkg_emit_error("error writing public key: %s",
		    ERR_error_string(ERR_get_error(), errbuf));
		BIO_free(bp);
		return (EPKG_FATAL);
	}

	*pubkeylen = BIO_get_mem_data(bp, pubkey);
	BIO_free(bp);
	return (EPKG_OK);
}

static int
mldsa_new(const char *name __unused, struct pkgsign_ctx *sctx __unused)
{

	SSL_load_error_strings();

	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();

	return (0);
}

static void
mldsa_free(struct pkgsign_ctx *sctx)
{
	struct mldsa_sign_ctx *keyinfo = MLDSA_CTX(sctx);

	if (keyinfo->key != NULL)
		EVP_PKEY_free(keyinfo->key);

	ERR_free_strings();
}

const struct pkgsign_ops pkgsign_mldsa = {
	.pkgsign_ctx_size = sizeof(struct mldsa_sign_ctx),
	.pkgsign_new = mldsa_new,
	.pkgsign_free = mldsa_free,

	.pkgsign_sign = mldsa_sign,
	.pkgsign_verify = mldsa_verify,
	.pkgsign_verify_cert = mldsa_verify_cert,

	.pkgsign_generate = mldsa_generate,
	.pkgsign_pubkey = mldsa_pubkey,
	.pkgsign_sign_data = mldsa_sign_data,
};
#endif	/* OPENSSL_VERSION_NUMBER >= 0x30500000L */
