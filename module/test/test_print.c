#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE_PATH "/dev/firewall_ctrl"
#define READ_BUF_SIZE 1024

void write_command(int fd, char command) {
    ssize_t bytes_written = write(fd, &command, 1);
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        exit(EXIT_FAILURE);
    }
    printf("Wrote command 0x%x to the device\n", command);
}

int main() {
    int fd;
    char read_buf[READ_BUF_SIZE];
    ssize_t bytes_read;
    size_t total_bytes_read = 0;

    // 打开设备
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device");
        return EXIT_FAILURE;
    }

    // 写入命令 0x4
    write_command(fd, 0x4);

    // 读取数据
    printf("Reading data from the device:\n");
    while ((bytes_read = read(fd, read_buf, sizeof(read_buf) - 1)) > 0) {
        read_buf[bytes_read] = '\0'; // 确保字符串以 null 结尾
        printf("%s", read_buf);
        total_bytes_read += bytes_read;
    }

    if (bytes_read < 0) {
        perror("Failed to read from the device");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("\nTotal bytes read: %zu\n", total_bytes_read);

    close(fd);
    return 0;
}