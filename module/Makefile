.PHONY: all clean install uninstall test rebuild $(TEST_PROGRAMS) test_print
obj-m += firewall.o 
PWD := $(CURDIR)
BUILD_DIR := $(PWD)/build
firewall-objs := main.o rule_filter.o driver.o stateful_check.o log.o nat.o
TEST_DIR := $(PWD)/test
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.c)
TEST_PROGRAMS := $(patsubst $(TEST_DIR)/%.c,%,$(TEST_SOURCES))

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mkdir -p $(BUILD_DIR)
	mv *.o *.ko *.mod.c .*.cmd Module.symvers modules.order $(BUILD_DIR)
	echo "Module built successfully"

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf $(BUILD_DIR)
	rm -f $(TEST_PROGRAMS)
	echo "Module cleaned successfully"

install:
	sudo insmod $(BUILD_DIR)/firewall.ko
	echo "Module installed successfully"

uninstall:
	sudo rmmod firewall
	echo "Module uninstalled successfully"

test: $(TEST_PROGRAMS)
	for prog in $(TEST_PROGRAMS); do \
		./$$prog; \
	done

$(TEST_PROGRAMS): %: $(TEST_DIR)/%.c
	gcc -o $@ $<
	./$@

rebuild: 
	$(MAKE) uninstall
	$(MAKE) clean
	$(MAKE) all
	$(MAKE) install