CC = gcc
CXX = g++

DEBUG_OPTIONS = -ggdb 
LINK_FLAGS = -o
MATH_FLAG = -lm
DYN_LIB_FLAG = -ldl
OPENMP_PARALLEL_FLAG = -fopenmp
OTHER_FLAGS = -lrt
COMPILATION_FLAGS = -g -c -Wall -ansi -pedantic -Wimplicit-function-declaration
OPENSSL_FLAG = -lcrypto
	
	
aes_cbc_openssl.o : aes_cbc_openssl.c
	$(CC) $(COMPILATION_FLAGS) $(DEBUG_OPTIONS) aes_cbc_openssl.c		
	
aes_cbc_openssl_standalone_test.o : aes_cbc_openssl_standalone_test.c
	$(CC) $(COMPILATION_FLAGS) $(DEBUG_OPTIONS) aes_cbc_openssl_standalone_test.c
	
linkaescbc :
	$(CC) $(LINK_FLAGS) AESCBCOpenssl \
	aes_cbc_openssl_standalone_test.o \
	aes_cbc_openssl.o \
	$(OPENSSL_FLAG)	

allaescbc : aes_cbc_openssl_standalone_test.o \
				aes_cbc_openssl.o
				
runaescbc : allaescbc linkaescbc

clean :
	rm -rfv *.o
	rm -rfv AESCBCOpenssl
