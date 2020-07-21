all: fuzzer qemu

fuzzer:
	mkdir -p build
	cd build && cmake ..
	$(MAKE) -C build
	cp build/weizz .
	cp build/weizz-* .

qemu:
	cd qemu-tracer && ./build-weizz.sh

clean:
	rm -rf build weizz-qemu weizz-showmap
	make -C qemu-tracer clean
