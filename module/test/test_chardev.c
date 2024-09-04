#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE_PATH "/dev/firewall_ctrl"

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
    char read_buf[100];
    ssize_t bytes_read;

    // 打开设备
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device");
        return EXIT_FAILURE;
    }

    // 写入命令 0x1
    write_command(fd, 0x1);

    // 读取数据
    bytes_read = read(fd, read_buf, sizeof(read_buf) - 1);
    if (bytes_read < 0) {
        perror("Failed to read from the device");
        close(fd);
        return EXIT_FAILURE;
    }
    read_buf[bytes_read] = '\0'; // 确保字符串以 null 结尾
    printf("Read %zd bytes from the device: %s\n", bytes_read, read_buf);

    // 写入命令 0x2
    write_command(fd, 0x2);

    // 读取数据
    bytes_read = read(fd, read_buf, sizeof(read_buf) - 1);
    if (bytes_read < 0) {
        perror("Failed to read from the device");
        close(fd);
        return EXIT_FAILURE;
    }
    read_buf[bytes_read] = '\0'; // 确保字符串以 null 结尾
    printf("Read %zd bytes from the device: %s\n", bytes_read, read_buf);

    // 写入命令 0x3
    write_command(fd, 0x3);

    // 读取数据
    bytes_read = read(fd, read_buf, sizeof(read_buf) - 1);
    if (bytes_read < 0) {
        perror("Failed to read from the device");
        close(fd);
        return EXIT_FAILURE;
    }
    read_buf[bytes_read] = '\0'; // 确保字符串以 null 结尾
    printf("Read %zd bytes from the device: %s\n", bytes_read, read_buf);

    // 关闭设备
    close(fd);
    return EXIT_SUCCESS;
}