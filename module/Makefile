.PHONY: all clean install uninstall test
obj-m += firewall.o
PWD := $(CURDIR)
BUILD_DIR := $(PWD)/build
firewall-objs := main.o rule_filter.o driver.o # 确保这里使用正确的文件名
TEST_PROGRAM = test_chardev
TEST_SOURCE = test_chardev.c
TEST_dir = $(PWD)/test
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mkdir -p $(BUILD_DIR)
	mv *.o *.ko *.mod.c .*.cmd $(BUILD_DIR)

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf $(BUILD_DIR)

install:
	sudo insmod $(BUILD_DIR)/firewall.ko

uninstall:
	sudo rmmod firewall

test:
	gcc -o $(TEST_PROGRAM) $(TEST_dir)/$(TEST_SOURCE)
	./$(TEST_PROGRAM)
	rm $(TEST_PROGRAM)
