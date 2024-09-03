obj-m += firewall.o
PWD := $(CURDIR)
BUILD_DIR := $(PWD)/build
firewall-objs := main.o tcp.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mkdir -p $(BUILD_DIR)
	mv *.o *.ko *.mod.c .*.cmd $(BUILD_DIR)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf $(BUILD_DIR)

install:
	insmod $(BUILD_DIR)/firewall.ko

uninstall:
	rmmod firewall