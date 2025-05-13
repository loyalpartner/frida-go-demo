# https://github.com/frida/frida-go/issues/37
build:
	CGO_CFLAGS="-Wno-error=incompatible-pointer-types" go build main.go

build2:
	cd ringbuffer
	CGO_CFLAGS="-Wno-error=incompatible-pointer-types" go build ./
