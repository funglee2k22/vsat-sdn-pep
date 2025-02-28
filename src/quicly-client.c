
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
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
#include "vsat-cpep-shared.h"


/*
 *  thread to handle one set connections, TCP conn and QUIC conn 
 *  @param data the thread data 
 *  @return NULL
 */
void *handle_client(void *data) 
{
    thread_data_t *d = (thread_data_t *)data;
    int clt_fd = d->tcp_sk;      //incoming TCP socket 
    char *quic_srv = d->quic_srv;
    short quic_port = d->quic_srv_port;
    int ret = 0;

    struct sockaddr_storage orig_dst;
    if (get_original_dest_addr(clt_fd, &orig_dst) != 0) {
        perror("failed to get original destination address");
        goto error;
    }

    // create quic client, stream and connected to the QUIC server
    quicly_stream_t *stream;
    quicly_conn_t *client = NULL;
    struct sockaddr_storage sa;
    socklen_t salen;
    ret = create_quic_client(stream, client, &sa, &salen, quic_srv, quic_port); 
    if (ret != 0) {
        perror("failed to create QUIC client");
        goto error;
    }

    // send the first message (pep header) to the server, server will use this infor
    // to a create a new TCP connection towards the Internet server.  
    pep_header_t pep_header = { .addr = orig_dst };
    
    if (send_quicly_message(stream, (void *) &pep_header, sizeof(pep_header)) != 0) {
        perror("failed to send PEP header");
        goto error;
    }

error:
    close(clt_fd);
    free(data);
    return NULL;
}


int run_client_loop(int listen_fd, char *quic_srv, short quic_port)
{
    struct sockaddr_in tcp_remote_addr;
    socklen_t tcp_addr_len = sizeof(tcp_remote_addr); 
    int ret = 0;
    
    while (1) { 
        int client_fd = accept(listen_fd, (struct sockaddr *)&tcp_remote_addr, &tcp_addr_len);
        if (client_fd < 0) {
            perror("accept: ");
            close(listen_fd);
            return -1;
        } 
        printf("Accepted connection from %s:%d\n", inet_ntoa(tcp_remote_addr.sin_addr), ntohs(tcp_remote_addr.sin_port));
        //create a new thread to handle the connection
        pthread_t thread;
        thread_data_t *data = (thread_data_t *)malloc(sizeof(data));
        if (data == NULL) { 
            perror("Failed to allocated memory for thread data. malloc: ");
            close(client_fd);
            continue;
        } 

        data->tcp_sk = client_fd;
        data->quic_srv = quic_srv; 
        data->quic_srv_port = quic_port;

        if (pthread_create(&thread, NULL, handle_client, (void *)data) != 0) {
            perror("Failed to create thread: ");
            close(client_fd);
            free(data);
            continue;
        }
        pthread_detach(thread);
    }
    return 0;
}

int main(int argc, char **argv)
{ 
    char *host = "127.0.0.1";     //quic server address 
    short port = 4433, tcp_listen_port = 443;   //port is quic server listening UDP port 
    char *cert_path = "server.crt";
    char *key_path = "server.key";
    
    int tcp_fd, quic_fd;  
    quicly_stream_t *stream;
    quicly_conn_t *client = NULL;
    int ret = 0;

    //TODO: resolve command line options and arguments
    //setup the quic and quicly context 
    //ctx is a global variable will be modifed by this function.  
    if ((ret = setup_ctx_quic(cert_path, key_path)) != 0) {
        fprintf(stderr, "failed to setup quic context: %d.\n", ret);
        exit(1);
    }

    //create a TCP listener 
    tcp_fd = create_tcp_listener(tcp_listen_port);
    if (tcp_fd < 0) {
        perror("failed to create TCP listener and terminating");
        exit(1);
    }

    run_client_loop(tcp_fd, host, port); 

    // TODO: add ing SIGNAL handling here
    close(tcp_fd); 

    return 0;
}
