CC=clang
CFLAGS=-fobjc-arc -fobjc-link-runtime -framework Foundation src/libcapstone.a

build/mackextdump:
	mkdir -p build;
	$(CC) $(CFLAGS) src/*.m -o $@

.PHONY:install
install:build/mackextdump
	mkdir -p /usr/local/bin
	cp build/mackextdump /usr/local/bin/mackextdump

.PHONY:uninstall
uninstall:
	rm /usr/local/bin/mackextdump

.PHONY:clean
clean:
	rm -rf build
