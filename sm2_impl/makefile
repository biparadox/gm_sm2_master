# makefile for sm2 lib
# linux platform
# if android, please reference to Android.mk
# Author : Simon Pang of catt2009 / steven.psm@gmail.com 
# 2012-6-22



LIBNAME=libsm2So.so
OBJECTS=sm2.o sm3.o sm2_Intrfs_test.o
CC=gcc
CPP=g++

#CFLAGS  =  -I./   -fPIC -g -D_DEBUG
CFLAGS  =  -I./   -fPIC -g 

all: $(LIBNAME)


$(LIBNAME):  $(OBJECTS)
	$(CC) $(CFLAGS)  $(OBJECTS) ../libtommath-0.42.0/libtommath.a -shared -o $(LIBNAME) -ldl

.cpp.o:
	$(CPP) $(CFLAGS) $< -o $@ -c
.c.o:
	$(CC) $(CFLAGS) $< -o $@ -c 

.PHONY:clean
clean:
	-rm $(LIBNAME) $(OBJECTS)
