#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

typedef struct { 
    struct sockaddr_storage addr;
} pep_header_t;

typedef struct {
    int tcp_sk; //
    char *quic_srv; 
    short quic_srv_port;  
} thread_data_t;

//global variables 
static quicly_context_t ctx;  //the QUIC context
static quicly_cid_plaintext_t next_cid; // the CID seed 

// TCP Listener 
int create_tcp_listener(short port); 

//TLS Key and Certificates handling 
static int load_private_key(ptls_openssl_sign_certificate_t *psign_certificate, char *key_path); 
static int load_certificates(ptls_context_t *tlsctx, char *cert_path);
static int setup_ctx_quic(char *cert_path, char *key_path);


// QUIC stock and stream related functions 
int create_udp_clt_socket(char *hostname, short port, struct sockaddr_storage *sa, socklen_t *salen);
int create_quic_clt_stream(quicly_conn_t *client, quicly_stream_t *stream, char *host, struct sockaddr_storage *sa);

int send_one(int fd, struct sockaddr *dest, struct iovec *vec);
int get_original_dest_addr(int fd, struct sockaddr_storage *dst_addr);


