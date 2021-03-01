#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <string.h>

#include "rsa.h"

#define RSA_ENCRYPT 0
#define RSA_DECRYPT 1

#define ERROR(x) printf(x); fflush(stdout); exit(EXIT_FAILURE);

/**
 * @brief 
 * 
 * @param argc length of command line args
 * @param argv array of command line args
 * @return int exit code
 */
int main(int argc, char* argv[]) {

    int mode;
    size_t stdin_buf_size = 10000;

    private_key d_key = {};
    public_key e_key = {};

    // parse command line arguments
    for(unsigned int i = 1; i < argc; i++) {
        if(argv[i][0] == 'e') {
            mode = RSA_ENCRYPT;
            if(i+1 < argc && i+2 < argc) {
                e_key.n = strtoumax(argv[i+1], NULL, 10);
                e_key.e = strtoumax(argv[i+2], NULL, 10);
                i += 2;
            }
            else {
                ERROR("malformed command line arguments");
            }

        }
        else if(argv[i][0] == 'd') {
            mode = RSA_DECRYPT;
            if(i+1 < argc && i+2 < argc) {
                d_key.n = strtoumax(argv[i+1], NULL, 10);
                d_key.d = strtoumax(argv[i+2], NULL, 10);
                i += 2;
            }
            else {
                ERROR("malformed command line arguments");
            }
        }
        else if(argv[i][0] == 'g') {
           generate_keys();
           exit(EXIT_SUCCESS);
        }
        else if(argv[i][0] == 's') {
            if(i+1 < argc) {
                stdin_buf_size = (size_t)strtoumax(argv[i+1], NULL, 10);
                ++i;
            }
            else {
                ERROR("malformed command line arguments");
            }
        }
        else if(isdigit(argv[i][0])) {
            stdin_buf_size = (size_t)strtoumax(argv[i], NULL, 10);
        }
    }

    // get input until EOF from stdin
    char *buf = calloc(stdin_buf_size, 1);
    while(fgets(buf, stdin_buf_size, stdin)) { }

    // get the real size of the input
    // doesn't count the empty space in the buffer
    size_t input_size;
    for(input_size = stdin_buf_size - 1; input_size >= 0 && buf[input_size] == '\0'; input_size--) { }

    rsa_buffer input_rsa_buf = {input_size, buf};
    rsa_buffer output_rsa_buf;

    if(mode == RSA_ENCRYPT) {
        // use_public_key((public_key){3233, 17});
        use_public_key(e_key);
        output_rsa_buf = encrypt(input_rsa_buf);
    }
    else if(mode == RSA_DECRYPT) {
        // use_private_key((private_key){3233, 413});
        use_private_key(d_key);
        output_rsa_buf = decrypt(input_rsa_buf);
    }

    printf("\n");

}