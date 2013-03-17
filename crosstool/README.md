用crosstool-ng建立交叉编译工具链

交叉编译说实话确实太复杂,不使用工具的话很容易陷入死循环里找不到解决方案...  
特别是对于新手来说,使用工具可以大大减少出错的几率.

#安装
我使用的Linux发行版是Archlinux,安装步骤很简单 yaourt -S crosstool-ng
软件的官方网址是:[crosstool-ng](http://crosstool-ng.org/)也可以直接去
官网下载安装

#配置
配置crosstool-ng工具才是最复杂的,因为配置文件稍有不对都会导致交叉编译工具链
的参数无法满足路由器平台的需求,导致软件无法运行,安装之后建立一个交叉编译的
文件夹, mkdir crosstool ,然后在这个文件夹打开终端,运行ct-ng menuconfig
开始进行参数的配置

##Paths and misc options
Local tarballs directory 设置交叉编译需要的包的目录  
Prefix directory 设置制作好的编译器的目录

##Target options
Target Architecture 目标架构,我的路由器选择的是mips   
Endianness 这个是字节序,mips平台是大端字节序,mipsel是小端字节序,我选择的大端字节序  
Floating point 浮点运算,这个我是选择的默认的hardware

##Toolchain options
(XXX) Tuple's vendor string 这里是修改个性化名称的地方

##Operating System
Target OS 这里毫无疑问选择Linux  
Linux kernel version 尽量版本低些和路由器内核接近,我选择的是 2.6.36.4

##Binary utilities 
binutils version 这里我选择 2.21.1a

##C compiler
gcc version 这里我选择的是4.6.3

##C-library
C library 嵌入式的C库一般都是uClibc  
uClibc version 0.9.33.2  
Configuration file 这是C库的配置文件,我会提供一个给大家的

其余的选择默认配置就好,配置好保存即可.我为大家提供了一个config例子

#编译
在终端里执行 ct-ng build,然后等待完成即可.

#设置环境变量
我的交叉编译工具链生成的地方是 /home/acgotaku/x-tools/mips-Arch-linux-uclibc
所以编辑 .bashrc文件
添加: export PATH=/home/acgotaku/x-tools/mips-Arch-linux-uclibc/bin:$PATH  
然后重启X或者注销重新登录,即可像 ls,cd命令那样使用mips-Arch-linux-uclibc-gcc命令  
至此,交叉编译工具链的配置和生成完成
