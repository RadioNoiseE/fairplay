SDK          =`xcrun --sdk iphoneos --show-sdk-path`
GCC_BIN      =`xcrun --sdk iphoneos --find gcc`
GCC_BASE     = $(GCC_BIN) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK) -F$(SDK)/System/Library/Frameworks -F$(SDK)/System/Library/PrivateFrameworks
GCC_UNIVERSAL=$(GCC_BASE) -arch arm64

all: fairplay.dylib

fairplay.dylib: fairplay.o 
	$(GCC_UNIVERSAL) -dynamiclib -o $@ $^

%.o: %.c
	$(GCC_UNIVERSAL) -c -o $@ $< 

clean:
	rm -f *.o fairplay.dylib
