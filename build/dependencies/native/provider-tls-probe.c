#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
}

static void handshake_step(SSL *ssl) {
    int result = SSL_do_handshake(ssl);
    if (result != 1) {
        int error = SSL_get_error(ssl, result);
        require(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE,
                "TLS handshake failed");
    }
}

static void exchange(int version, EVP_PKEY *key, X509 *certificate, int mode) {
    SSL_CTX *client_context = SSL_CTX_new(TLS_method());
    SSL_CTX *server_context = SSL_CTX_new(TLS_method());
    SSL *client, *server;
    BIO *client_io = NULL, *server_io = NULL;
    char received[32];
    const char message[] = "source-provider-tls";
    int rounds, rejected = 0;
    long expected = mode == 1 ? X509_V_ERR_HOSTNAME_MISMATCH
                             : X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
    require(client_context && server_context, "TLS context allocation failed");
    require(SSL_CTX_set_min_proto_version(client_context, version) == 1
            && SSL_CTX_set_max_proto_version(client_context, version) == 1
            && SSL_CTX_set_min_proto_version(server_context, version) == 1
            && SSL_CTX_set_max_proto_version(server_context, version) == 1,
            "Requested TLS version is unavailable");
    require(SSL_CTX_use_certificate(server_context, certificate) == 1
            && SSL_CTX_use_PrivateKey(server_context, key) == 1
            && SSL_CTX_check_private_key(server_context) == 1,
            "Ephemeral server identity failed");
    if (mode != 2) {
        require(X509_STORE_add_cert(SSL_CTX_get_cert_store(client_context), certificate) == 1,
                "Ephemeral trust anchor failed");
    }
    SSL_CTX_set_verify(client_context, SSL_VERIFY_PEER, NULL);
    client = SSL_new(client_context);
    server = SSL_new(server_context);
    require(client && server && BIO_new_bio_pair(&client_io, 0, &server_io, 0) == 1,
            "TLS endpoint allocation failed");
    SSL_set_bio(client, client_io, client_io);
    SSL_set_bio(server, server_io, server_io);
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);
    require(SSL_set1_host(client, mode == 1 ? "not-localhost.invalid" : "localhost") == 1
            && SSL_set_tlsext_host_name(client, "localhost") == 1,
            "TLS hostname setup failed");
    for (rounds = 0; rounds < 10000; ++rounds) {
        int result = SSL_do_handshake(client);
        if (result != 1) {
            int error = SSL_get_error(client, result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                require(mode != 0 && error == SSL_ERROR_SSL
                        && SSL_get_verify_result(client) == expected,
                        "Unexpected client TLS failure");
                rejected = 1;
                break;
            }
        }
        handshake_step(server);
        if (SSL_is_init_finished(client) && SSL_is_init_finished(server)) break;
    }
    if (mode != 0) {
        require(rejected && !SSL_is_init_finished(client),
                "TLS accepted an invalid peer or failed to reject it");
        printf("%s rejected-%s verify=%ld\n",
               version == TLS1_2_VERSION ? "TLSv1.2" : "TLSv1.3",
               mode == 1 ? "hostname" : "untrusted", expected);
        ERR_clear_error();
    } else {
        require(rounds < 10000 && SSL_get_verify_result(client) == X509_V_OK,
                "TLS handshake/peer verification did not complete");
        require(SSL_write(client, message, sizeof(message)) == sizeof(message)
                && SSL_read(server, received, sizeof(received)) == sizeof(message)
                && memcmp(message, received, sizeof(message)) == 0,
                "Authenticated TLS application data differs");
        printf("%s %s verified-hostname authenticated-data\n", SSL_get_version(client),
               SSL_get_cipher_name(client));
    }
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(client_context);
    SSL_CTX_free(server_context);
}

int main(void) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    X509 *certificate = X509_new();
    X509_NAME *name;
    X509_EXTENSION *san;
    require(key && certificate, "Ephemeral identity allocation failed");
    require(X509_set_version(certificate, 2) == 1
            && ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) == 1
            && X509_gmtime_adj(X509_getm_notBefore(certificate), -60) != NULL
            && X509_gmtime_adj(X509_getm_notAfter(certificate), 3600) != NULL
            && X509_set_pubkey(certificate, key) == 1, "Ephemeral certificate setup failed");
    name = X509_get_subject_name(certificate);
    require(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                (const unsigned char *)"localhost", -1, -1, 0) == 1
            && X509_set_issuer_name(certificate, name) == 1, "Ephemeral certificate name failed");
    san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, "DNS:localhost");
    require(san && X509_add_ext(certificate, san, -1) == 1,
            "Ephemeral certificate SAN failed");
    X509_EXTENSION_free(san);
    require(X509_sign(certificate, key, EVP_sha256()) > 0, "Ephemeral certificate signing failed");
    exchange(TLS1_2_VERSION, key, certificate, 0);
    exchange(TLS1_2_VERSION, key, certificate, 1);
    exchange(TLS1_2_VERSION, key, certificate, 2);
    exchange(TLS1_3_VERSION, key, certificate, 0);
    exchange(TLS1_3_VERSION, key, certificate, 1);
    exchange(TLS1_3_VERSION, key, certificate, 2);
    X509_free(certificate);
    EVP_PKEY_free(key);
    return 0;
}
