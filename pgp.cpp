// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <gpgme.h>
#include <weechat/weechat-plugin.h>

#include "plugin.hh"
#include "pgp.hh"

#define PGP_MESSAGE_HEADER "-----BEGIN PGP MESSAGE-----\r\n"
#define PGP_MESSAGE_FOOTER "\r\n-----END PGP MESSAGE-----"
#define PGP_SIGNATURE_HEADER "-----BEGIN PGP SIGNATURE-----\r\n"
#define PGP_SIGNATURE_FOOTER "\r\n-----END PGP SIGNATURE-----"

const char *PGP_ADVICE = "[PGP encrypted message (XEP-0027)]";

void pgp__init(struct t_pgp **pgp, const char *pub, const char *sec)
{
    struct t_pgp *new_pgp;
    gpgme_error_t err;
	gpgme_data_t keydata;

    gpgme_check_version(NULL);

    new_pgp = (struct t_pgp*)calloc(1, sizeof(**pgp));

    err = gpgme_new(&new_pgp->gpgme);
    if (err) {
        return;
    }
    gpgme_set_armor(new_pgp->gpgme, true);

    err = gpgme_data_new_from_file(&keydata, pub, true);
    if (err) {
        return;
    }

    err = gpgme_op_import(new_pgp->gpgme, keydata);
    if (err) {
        return;
    }

    gpgme_import_result_t impRes = gpgme_op_import_result(new_pgp->gpgme);
    weechat_printf(nullptr, "(gpg) imported %d keys", impRes->imported);

    err = gpgme_data_new_from_file(&keydata, sec, true);
    if (err) {
        return;
    }

    err = gpgme_op_import(new_pgp->gpgme, keydata);
    if (err) {
        return;
    }

    impRes = gpgme_op_import_result(new_pgp->gpgme);
    weechat_printf(nullptr, "(gpg) imported %d secret keys", impRes->imported);

    *pgp = new_pgp;
}

void pgp__free(struct t_pgp *pgp)
{
    if (pgp)
    {
        if (pgp->gpgme)
            gpgme_release(pgp->gpgme);
        free(pgp);
    }
}

char *pgp__encrypt(struct t_gui_buffer *buffer, struct t_pgp *pgp, const char *source, const char *target, const char *message)
{
    std::string encrypted;
    gpgme_key_t keys[3] = {NULL,NULL,NULL};
    char *           result = NULL;

    int ret;
    gpgme_error_t err;
    gpgme_data_t in, out;

	/* Initialize input buffer. */
	err = gpgme_data_new_from_mem(&in, message, strlen(message), false);
    if (err) {
        goto encrypt_finish;
    }

	/* Initialize output buffer. */
	err = gpgme_data_new(&out);
    if (err) {
        goto encrypt_finish;
    }

	/* Encrypt data. */
	err = gpgme_get_key(pgp->gpgme, target, &keys[0], false);
    if (err) {
        goto encrypt_finish;
    }
	err = gpgme_get_key(pgp->gpgme, source, &keys[1], false);
    if (err) {
        goto encrypt_finish;
    }
    err = gpgme_op_encrypt(pgp->gpgme, keys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (err) {
        goto encrypt_finish;
    }
	if (gpgme_encrypt_result_t enc_result = gpgme_op_encrypt_result(pgp->gpgme);
            enc_result->invalid_recipients)
	{
        goto encrypt_finish;
	}
    gpgme_data_seek(out, 0, SEEK_SET);
    char data[512 + 1];
    while ((ret = gpgme_data_read(out, data, 512)) > 0)
    {
        encrypted += std::string_view(data, ret);
    }

	gpgme_data_release(in);
	gpgme_data_release(out);

    result = strndup(encrypted.data() + strlen(PGP_MESSAGE_HEADER),
                     encrypted.size() - strlen(PGP_MESSAGE_HEADER) - strlen(PGP_MESSAGE_FOOTER));
encrypt_finish:
    return result;
}

//"hQIMAzlgcSFDGLKEAQ//cGG3DFughC5xBF7xeXz1RdayOfhBAPfoZIq62MVuSnfS\nMfig65Zxz1LtAnnFq90TZY7hiHPBtVlYqg47AbSoYweMdpXsKgbUrd3NNf6k2nsZ\nUkChCtyGuHi8pTzclfle7gT0nNXJ1WcLCZ4ORZCrg3D5A+YTO9tdmE8GQsTT6TdV\nbbxF5yR4JF5SzFhuFL3ZoXPXrWylcwKXarYfoOTa6M2vSsCwApVIXQgJ/FI46sLT\nb0B/EVCjFvcvjkNr7+K7mQtth+x0a0pC4BtEhRvnIRAe/sdGp8NY+DP76clx4U+k\nIDG4H92F632pR6eEIoZttnBoaj0O4sTVAJCao5AoecR4w2FDqBWWtIyQp5vbo17/\nMtzungkk5vQP6Jhu36wa+JKpbHoxomVpHPZfAtIoyaY6pzQ0bUomIlSVpbZDvF68\nZKTlFd89Pm5x0JO5gsVYvf+N9Ed33d34n/0CFz5K5Tgu4Bk0v4LWEy3wtNsuQB4p\nkBSZJk7I2BakcRwP0zwld6rRHFIX1pb7zqThBPZGB9RkWPltiktUTibOII12tWhi\nksFpQJ8l1A8h9vM5kUXIeD6H2yP0CBUEIZF3Sf+jiSRZ/1/n3KoUrKEzkf/y4xgv\n1LA4pMjNLEr6J2fqGyYRFv4Bxv3PIvF17V5CwOtguxGRJHJXdIzm1BSHSqXxHezS\nYAFXMUb9fw3QX7Ed23KiyZjzd/LRsQBqMs9RsYyZB2PqF9x84lQYYbE8lErrryvK\nUEtmJKPw3Hvb7kgGox5vl5+KCg9q64EU9TgQpufYNShKtDz7Fsvc+ncgZoshDUeo\npw==\n=euIB"
char *pgp__decrypt(struct t_gui_buffer *buffer, struct t_pgp *pgp, const char *ciphertext)
{
    std::string decrypted;
    uint8_t *    buf = NULL;
    size_t       buf_len = 0;
    char *       result = NULL;

    int ret;

    buf_len = strlen(PGP_MESSAGE_HEADER) + strlen(ciphertext) + strlen(PGP_MESSAGE_FOOTER) + 1;
    buf = (uint8_t*)malloc(sizeof(char) * buf_len);
    buf_len = snprintf((char *)buf, buf_len, PGP_MESSAGE_HEADER "%s" PGP_MESSAGE_FOOTER, ciphertext);

    gpgme_error_t err;
    gpgme_data_t in, out;

	/* Initialize input buffer. */
	err = gpgme_data_new_from_mem(&in, (char *)buf, buf_len, false);
    if (err) {
        goto decrypt_finish;
    }

	/* Initialize output buffer. */
	err = gpgme_data_new(&out);
    if (err) {
        goto decrypt_finish;
    }

	/* Decrypt data. */
    err = gpgme_op_decrypt(pgp->gpgme, in, out);
    if (err) {
        goto decrypt_finish;
    }
	if (gpgme_decrypt_result_t dec_result = gpgme_op_decrypt_result(pgp->gpgme);
            dec_result->unsupported_algorithm)
	{
        goto decrypt_finish;
	}
    gpgme_data_seek(out, 0, SEEK_SET);
    char data[512 + 1];
    while ((ret = gpgme_data_read(out, data, 512)) > 0)
    {
        decrypted += std::string_view(data, ret);
    }

	gpgme_data_release(in);
	gpgme_data_release(out);

    result = strndup(decrypted.data(), decrypted.size());
decrypt_finish:
    return result;
}

char *pgp__verify(struct t_gui_buffer *buffer, struct t_pgp *pgp, const char *certificate)
{
    uint8_t *       buf = NULL;
    size_t          buf_len = 0;
    size_t          sigcount = 0;
    char *          result = NULL;

    int ret;

    buf_len = strlen(PGP_SIGNATURE_HEADER) + strlen(certificate) + strlen(PGP_SIGNATURE_FOOTER) + 1;
    buf = (uint8_t*)malloc(sizeof(char) * buf_len);
    buf_len = snprintf((char *)buf, buf_len, PGP_SIGNATURE_HEADER "%s" PGP_SIGNATURE_FOOTER, certificate);

	gpgme_verify_result_t vrf_result;
    gpgme_error_t err;
    gpgme_data_t in, out;

	/* Initialize input buffer. */
	err = gpgme_data_new_from_mem(&in, (char *)buf, buf_len, false);
    if (err) {
        goto verify_finish;
    }

	/* Initialize output buffer. */
	err = gpgme_data_new(&out);
    if (err) {
        goto verify_finish;
    }

	/* Verify data. */
    err = gpgme_op_verify(pgp->gpgme, in, out, nullptr);
    if (err) {
        goto verify_finish;
    }
	if (vrf_result = gpgme_op_verify_result(pgp->gpgme);
            !(vrf_result->signatures->summary & GPGME_SIGSUM_VALID))
	{
        goto verify_finish;
	}

    result = strdup(vrf_result->signatures->fpr);

verify_finish:
    return result;
}

char *pgp__sign(struct t_gui_buffer *buffer, struct t_pgp *pgp, const char *source, const char *message)
{
    std::string signature;
    uint8_t *        buf = NULL;
    size_t           buf_len = 0;
    char *           result = NULL;
    int ret;

    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_key_t key;

	/* Initialize input buffer. */
	err = gpgme_data_new_from_mem(&in, (char *)message, strlen(message), false);
    if (err) {
        goto sign_finish;
    }

	/* Initialize output buffer. */
	err = gpgme_data_new(&out);
    if (err) {
        goto sign_finish;
    }

    /* Include signature within key. */
    {
        gpgme_keylist_mode_t kmode = gpgme_get_keylist_mode(pgp->gpgme);
        kmode |= GPGME_KEYLIST_MODE_SIGS;
        err = gpgme_set_keylist_mode(pgp->gpgme, kmode);
    }
    if (err) {
        goto sign_finish;
    }

	err = gpgme_get_key(pgp->gpgme, source, &key, false);
    if (err) {
        weechat_printf(nullptr, "(gpg) get key fail for %s", source);
        goto sign_finish;
    }
	err = gpgme_signers_add(pgp->gpgme, key);
    if (err) {
        weechat_printf(nullptr, "(gpg) add key fail for %s", source);
        goto sign_finish;
    }

	/* Sign data. */
    err = gpgme_op_sign(pgp->gpgme, in, out, GPGME_SIG_MODE_DETACH);
    if (err) {
        weechat_printf(nullptr, "(gpg) sign fail for %s", source);
        goto sign_finish;
    }
	if (gpgme_sign_result_t sgn_result = gpgme_op_sign_result(pgp->gpgme);
            !sgn_result->signatures)
	{
        weechat_printf(nullptr, "(gpg) signature fail for %s", source);
	}
    gpgme_data_seek(out, 0, SEEK_SET);
    char data[512 + 1];
    while ((ret = gpgme_data_read(out, data, 512)) > 0)
    {
        signature += std::string_view(data, ret);
    }

	gpgme_data_release(in);
	gpgme_data_release(out);

    result = strndup(signature.data() + strlen(PGP_SIGNATURE_HEADER),
                     signature.size() - strlen(PGP_SIGNATURE_HEADER) - strlen(PGP_SIGNATURE_FOOTER));
sign_finish:
    return result;
}
