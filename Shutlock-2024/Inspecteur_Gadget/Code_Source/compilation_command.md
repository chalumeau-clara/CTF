Compile with : 

```shell
└─$ mips64el-linux-gnuabi64-gcc -L libc.so.6 -o vuln -pie -fpie -fstack-protector -z noexecstack -g main.c
```