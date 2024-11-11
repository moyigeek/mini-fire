.PHONY: all module clean

module:
    $(MAKE) -C module

clean:
    $(MAKE) -C module clean