.PHONY: all module clean
module:
	cd ./module && make
	cd ..
clean:
	cd ./module && make clean
	cd ..