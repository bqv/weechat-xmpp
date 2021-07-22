// This Source Code Form is subject to the terms of the Mozilla PublicAA
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <rnp/rnp.h>
#include <weechat/weechat-plugin.h>

#include "plugin.h"
#include "pgp.h"

#define RNP_SUCCESS 0

#define PGP_MESSAGE_HEADER "-----BEGIN PGP MESSAGE-----\r\n\r\n"
#define PGP_MESSAGE_FOOTER "\r\n-----END PGP MESSAGE-----\r\n"

const char *PGP_ADVICE = "[PGP encrypted message (XEP-0027)]";

void pgp__init(struct t_pgp **pgp, const char *pub, const char *sec)
{
    struct t_pgp *new_pgp;
    rnp_input_t keyring;

    new_pgp = calloc(1, sizeof(**pgp));

    if (rnp_ffi_create(&new_pgp->context,
                       RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG) != RNP_SUCCESS) {
        return;
    }

    if (rnp_input_from_path(&keyring, pub) == RNP_SUCCESS) {
        if (rnp_load_keys(new_pgp->context, RNP_KEYSTORE_GPG,
                          keyring, RNP_LOAD_SAVE_PUBLIC_KEYS) == RNP_SUCCESS) {
            rnp_input_destroy(keyring);
        }
    }

    if (rnp_input_from_path(&keyring, sec) == RNP_SUCCESS) {
        if (rnp_load_keys(new_pgp->context, RNP_KEYSTORE_GPG,
                          keyring, RNP_LOAD_SAVE_SECRET_KEYS) == RNP_SUCCESS) {
            rnp_input_destroy(keyring);
        }
    }

    *pgp = new_pgp;
}

void pgp__free(struct t_pgp *pgp)
{
    if (pgp)
    {
        if (pgp->context)
            free(pgp->context);
        free(pgp);
    }
}

/* this simple helper function just prints armored key, searched by userid, to stdout */
static bool pgp__print_key(rnp_ffi_t rnp, const char *uid, bool secret)
{
    rnp_output_t     keydata = NULL;
    rnp_key_handle_t key = NULL;
    uint32_t         flags = RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_SUBKEYS;
    uint8_t *        buf = NULL;
    size_t           buf_len = 0;
    bool             result = false;

    /* you may search for the key via userid, keyid, fingerprint, grip */
    if (rnp_locate_key(rnp, "userid", uid, &key) != RNP_SUCCESS) {
        return false;
    }

    if (!key) {
        return false;
    }

    /* create in-memory output structure to later use buffer */
    if (rnp_output_to_memory(&keydata, 0) != RNP_SUCCESS) {
        goto finish;
    }

    flags = flags | (secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC);
    if (rnp_key_export(key, keydata, flags) != RNP_SUCCESS) {
        goto finish;
    }

    /* get key's contents from the output structure */
    if (rnp_output_memory_get_buf(keydata, &buf, &buf_len, false) != RNP_SUCCESS) {
        goto finish;
    }
    weechat_printf(NULL, "pgp: %.*s", (int) buf_len, buf);

    result = true;
finish:
    rnp_key_handle_destroy(key);
    rnp_output_destroy(keydata);
    return result;
}

static bool pgp__export_key(rnp_ffi_t rnp, const char *uid, bool secret)
{
    rnp_output_t     keyfile = NULL;
    rnp_key_handle_t key = NULL;
    uint32_t         flags = RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_SUBKEYS;
    char             filename[32] = {0};
    char *           keyid = NULL;
    bool             result = false;

    /* you may search for the key via userid, keyid, fingerprint, grip */
    if (rnp_locate_key(rnp, "userid", uid, &key) != RNP_SUCCESS) {
        return false;
    }

    if (!key) {
        return false;
    }

    /* get key's id and build filename */
    if (rnp_key_get_keyid(key, &keyid) != RNP_SUCCESS) {
        goto finish;
    }
    snprintf(filename, sizeof(filename), "key-%s-%s.asc", keyid, secret ? "sec" : "pub");
    rnp_buffer_destroy(keyid);

    /* create file output structure */
    if (rnp_output_to_path(&keyfile, filename) != RNP_SUCCESS) {
        goto finish;
    }

    flags = flags | (secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC);
    if (rnp_key_export(key, keyfile, flags) != RNP_SUCCESS) {
        goto finish;
    }

    result = true;
finish:
    rnp_key_handle_destroy(key);
    rnp_output_destroy(keyfile);
    return result;
}

char *pgp__encrypt(struct t_pgp *pgp, const char *target, const char *message)
{
    rnp_op_encrypt_t encrypt = NULL;
    rnp_key_handle_t key = NULL;
    rnp_input_t      keyfile = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    char *           result = NULL;

    rnp_result_t ret;

    /* create memory input and file output objects for the message and encrypted message */
    if ((ret = rnp_input_from_memory(&input, (uint8_t *)message, strlen(message), false)) !=
        RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to create input object: %s\n", reason);
        goto encrypt_finish;
    }

    if ((ret = rnp_output_to_memory(&output, 0)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to create output object: %s\n", reason);
        goto encrypt_finish;
    }

    /* create encryption operation */
    if ((ret = rnp_op_encrypt_create(&encrypt, pgp->context, input, output)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to create encrypt operation: %s\n", reason);
        goto encrypt_finish;
    }

    /* setup encryption parameters */
    rnp_op_encrypt_set_armor(encrypt, true);
    rnp_op_encrypt_set_file_name(encrypt, "message.txt");
    rnp_op_encrypt_set_file_mtime(encrypt, time(NULL));
    rnp_op_encrypt_set_compression(encrypt, "ZIP", 6);
    rnp_op_encrypt_set_cipher(encrypt, RNP_ALGNAME_AES_256);
    rnp_op_encrypt_set_aead(encrypt, "None");

    /* locate recipient's key and add it to the operation context. */
    if ((ret = rnp_locate_key(pgp->context, "keyid", target, &key)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to locate recipient key: %s\n", reason);
        goto encrypt_finish;
    }

    if ((ret = rnp_op_encrypt_add_recipient(encrypt, key)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to add recipient: %s\n", reason);
        goto encrypt_finish;
    }
    rnp_key_handle_destroy(key);
    key = NULL;

    /* execute encryption operation */
    if ((ret = rnp_op_encrypt_execute(encrypt)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: encryption failed: %s\n", reason);
        goto encrypt_finish;
    }

    uint8_t *buf;
    size_t buf_len;

    rnp_output_memory_get_buf(output, &buf, &buf_len, false);
    result = strndup((char *)buf + strlen(PGP_MESSAGE_HEADER),
                     buf_len - strlen(PGP_MESSAGE_HEADER) - strlen(PGP_MESSAGE_FOOTER));
encrypt_finish:
    rnp_op_encrypt_destroy(encrypt);
    rnp_input_destroy(keyfile);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);
    return result;
}

//"hQIMAzlgcSFDGLKEAQ//cGG3DFughC5xBF7xeXz1RdayOfhBAPfoZIq62MVuSnfS\nMfig65Zxz1LtAnnFq90TZY7hiHPBtVlYqg47AbSoYweMdpXsKgbUrd3NNf6k2nsZ\nUkChCtyGuHi8pTzclfle7gT0nNXJ1WcLCZ4ORZCrg3D5A+YTO9tdmE8GQsTT6TdV\nbbxF5yR4JF5SzFhuFL3ZoXPXrWylcwKXarYfoOTa6M2vSsCwApVIXQgJ/FI46sLT\nb0B/EVCjFvcvjkNr7+K7mQtth+x0a0pC4BtEhRvnIRAe/sdGp8NY+DP76clx4U+k\nIDG4H92F632pR6eEIoZttnBoaj0O4sTVAJCao5AoecR4w2FDqBWWtIyQp5vbo17/\nMtzungkk5vQP6Jhu36wa+JKpbHoxomVpHPZfAtIoyaY6pzQ0bUomIlSVpbZDvF68\nZKTlFd89Pm5x0JO5gsVYvf+N9Ed33d34n/0CFz5K5Tgu4Bk0v4LWEy3wtNsuQB4p\nkBSZJk7I2BakcRwP0zwld6rRHFIX1pb7zqThBPZGB9RkWPltiktUTibOII12tWhi\nksFpQJ8l1A8h9vM5kUXIeD6H2yP0CBUEIZF3Sf+jiSRZ/1/n3KoUrKEzkf/y4xgv\n1LA4pMjNLEr6J2fqGyYRFv4Bxv3PIvF17V5CwOtguxGRJHJXdIzm1BSHSqXxHezS\nYAFXMUb9fw3QX7Ed23KiyZjzd/LRsQBqMs9RsYyZB2PqF9x84lQYYbE8lErrryvK\nUEtmJKPw3Hvb7kgGox5vl5+KCg9q64EU9TgQpufYNShKtDz7Fsvc+ncgZoshDUeo\npw==\n=euIB"
char *pgp__decrypt(struct t_pgp *pgp, const char *ciphertext)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;
    uint8_t *    buf = NULL;
    size_t       buf_len = 0;
    char *       result = NULL;

    rnp_result_t ret;

    buf_len = strlen(PGP_MESSAGE_HEADER) + strlen(ciphertext) + strlen(PGP_MESSAGE_FOOTER) + 1;
    buf = malloc(sizeof(char) * buf_len);
    buf_len = snprintf((char *)buf, buf_len, PGP_MESSAGE_HEADER "%s" PGP_MESSAGE_FOOTER, ciphertext);

    /* create file input and memory output objects for the encrypted message and decrypted
     * message */
    if ((ret = rnp_input_from_memory(&input, buf, buf_len, false)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to create input object: %s\n", reason);
        goto decrypt_finish;
    }

    if ((ret = rnp_output_to_memory(&output, 0)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to create output object: %s\n", reason);
        goto decrypt_finish;
    }

    if ((ret = rnp_decrypt(pgp->context, input, output)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: public-key decryption failed: %s\n", reason);
        goto decrypt_finish;
    }
    free(buf);

    /* get the decrypted message from the output structure */
    if (rnp_output_memory_get_buf(output, &buf, &buf_len, false) != RNP_SUCCESS) {
        goto decrypt_finish;
    }

    result = strndup((const char *)buf, (int)buf_len);
decrypt_finish:
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    return result;
}

char *pgp__verify(struct t_pgp *pgp)
{
    rnp_op_verify_t verify = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;
    uint8_t *       buf = NULL;
    size_t          buf_len = 0;
    size_t          sigcount = 0;
    char *          result = NULL;

    rnp_result_t ret;

    /* create file input and memory output objects for the signed message and verified
     * message */
    if ((ret = rnp_input_from_path(&input, "signed.asc")) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to open file 'signed.asc'. Did you run the sign example?: %s\n", reason);
        goto verify_finish;
    }

    if ((ret = rnp_output_to_memory(&output, 0)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to create output object: %s\n", reason);
        goto verify_finish;
    }

    if ((ret = rnp_op_verify_create(&verify, pgp->context, input, output)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to create verification context: %s\n", reason);
        goto verify_finish;
    }

    if ((ret = rnp_op_verify_execute(verify)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to execute verification operation: %s\n", reason);
        goto verify_finish;
    }

    /* now check signatures and get some info about them */
    if ((ret = rnp_op_verify_get_signature_count(verify, &sigcount)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        weechat_printf(NULL, "pgp: failed to get signature count: %s\n", reason);
        goto verify_finish;
    }

    for (size_t i = 0; i < sigcount; i++) {
        rnp_op_verify_signature_t sig = NULL;
        rnp_result_t              sigstatus = RNP_SUCCESS;
        rnp_key_handle_t          key = NULL;
        char *                    keyid = NULL;

        if ((ret = rnp_op_verify_get_signature_at(verify, i, &sig)) != RNP_SUCCESS) {
            const char *reason = rnp_result_to_string(ret);
            weechat_printf(NULL, "pgp: failed to get signature %d: %s\n", (int)i, reason);
            goto verify_finish;
        }

        if ((ret = rnp_op_verify_signature_get_key(sig, &key)) != RNP_SUCCESS) {
            const char *reason = rnp_result_to_string(ret);
            weechat_printf(NULL, "pgp: failed to get signature's %d key: %s\n", (int)i, reason);
            goto verify_finish;
        }

        if ((ret = rnp_key_get_keyid(key, &keyid)) != RNP_SUCCESS) {
            const char *reason = rnp_result_to_string(ret);
            weechat_printf(NULL, "pgp: failed to get key id %d: %s\n", (int)i, reason);
            rnp_key_handle_destroy(key);
            goto verify_finish;
        }

        sigstatus = rnp_op_verify_signature_get_status(sig);
        weechat_printf(NULL, "pgp: Status for signature from key %s : %d\n", keyid, (int)sigstatus);
        result = strdup(keyid);
        rnp_buffer_destroy(keyid);
        rnp_key_handle_destroy(key);
    }

    /* get the verified message from the output structure */
    if ((ret = rnp_output_memory_get_buf(output, &buf, &buf_len, false)) != RNP_SUCCESS) {
        const char *reason = rnp_result_to_string(ret);
        (void) reason;
        goto verify_finish;
    }
    weechat_printf(NULL, "pgp: Verified message:\n%.*s\n", (int)buf_len, buf);

verify_finish:
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    return result;
}
