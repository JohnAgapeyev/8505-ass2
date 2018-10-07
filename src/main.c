#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"

bool use_aes = false;
bool out_bmp = false;
int bit_setting = 0;

#define usage() \
    do { \
        printf("Usage options:\n" \
               "\t[i]nput    - The input carrier file\n" \
               "\t[o]utput   - The output carrier file\n" \
               "\t[f]ile     - The data input/output file\n" \
               "\t[e]ncrypt  - Encrypt mode\n" \
               "\t[d]ecrypt  - Decrypt mode\n" \
               "\t[p]assword - The encryption password\n" \
               "\t[a]es      - Encrypt using AES-GCM instead of ChaCha20-Poly1305\n" \
               "\t[b]mp      - Write out a BMP file instead of a PNG file\n" \
               "\t[s]etting  - The bit number of each channel that will be modified (0-7, with 0 " \
               "being LSB)\n" \
               "\t[h]elp     - This message\n" \
               "Input, file, mode, and password are required arguments\n" \
               "Output file is required in encryption mode only\n"); \
    } while (0)

int main(int argc, char** argv) {
    int choice;
    const char* input_filename = NULL;
    const char* output_filename = NULL;
    const char* data_filename = NULL;
    const char* password = NULL;
    bool is_encrypt = false;
    bool mode_set = false;
    for (;;) {
        static struct option long_options[] = {{"help", no_argument, 0, 'h'},
                {"input", required_argument, 0, 'i'}, {"output", required_argument, 0, 'o'},
                {"encrypt", no_argument, 0, 'e'}, {"decrypt", no_argument, 0, 'd'},
                {"file", required_argument, 0, 'f'}, {"password", required_argument, 0, 'p'},
                {"aes", no_argument, 0, 'a'}, {"setting", required_argument, 0, 's'}, {0, 0, 0, 0}};

        int option_index = 0;
        if ((choice = getopt_long(argc, argv, "hi:o:f:p:abeds:", long_options, &option_index))
                == -1) {
            break;
        }

        switch (choice) {
            case 'i':
                input_filename = optarg;
                break;
            case 'o':
                output_filename = optarg;
                break;
            case 'e':
                if (mode_set) {
                    usage();
                    exit(EXIT_FAILURE);
                }
                is_encrypt = true;
                mode_set = true;
                break;
            case 'd':
                if (mode_set) {
                    usage();
                    exit(EXIT_FAILURE);
                }
                is_encrypt = false;
                mode_set = true;
                break;
            case 'f':
                data_filename = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'a':
                use_aes = true;
                break;
            case 'b':
                out_bmp = true;
                break;
            case 's':
                bit_setting = optarg[0] - '0';
                if (bit_setting < 0 || bit_setting > 7) {
                    usage();
                    exit(EXIT_FAILURE);
                }
                break;
            case 'h':
            case '?':
            default:
                usage();
                return EXIT_FAILURE;
        }
    }
    if (!input_filename || !password || !data_filename) {
        usage();
        return EXIT_FAILURE;
    }
    if (is_encrypt && !output_filename) {
        usage();
        return EXIT_FAILURE;
    }

    if (is_encrypt) {
        write_stego(input_filename, output_filename, data_filename, password);
    } else {
        if (!read_stego(input_filename, data_filename, password)) {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
