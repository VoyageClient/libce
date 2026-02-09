#include "libce/message.h"
#include "fuzzing.hh"

int main(int argc, const char *argv[]) {
    int message_fd = STDIN_FILENO;
    uint8_t * message_buffer;
    ssize_t message_length = check_errno(
        "Error reading message file", read_file(message_fd, &message_buffer)
    );
    _OlmMessageReader * reader = new _OlmMessageReader;
    _olm_decode_message(&*reader, message_buffer, message_length, 8);
    free(message_buffer);
    delete reader;

    return EXIT_SUCCESS;
}
