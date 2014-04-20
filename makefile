gcc -shared -Wl,-soname,c_func_mpotr -o c_func_mpotr.so -fPIC c_func_mpotr.c `libgcrypt-config --cflags --libs`
