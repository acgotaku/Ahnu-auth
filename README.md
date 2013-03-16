安徽师范大学校园网认证 for Linux and mips

#校园网内网认证
众所周知,安师大校园网内网认证采用的锐捷认证,网上已经有比较成熟的mentohust

##内网认证 for Linux
想必各个发行版都已经有编译好的成品了,我也放了0.3.1版本的mentohust源码在里面
编译和安装三部曲

	./configure --prefix=/usr
	make
	make install

##外网认证 for mips
MIPS其实就是我的路由器的平台,型号是TP-LINK TL-WR841N V7版本,由于官方是中文的
导致路由器乱码问题,所以我简单的翻译成了英文.我已经交叉编译好了一个MIPS版本的
mentohust在文件夹里
如果想自己交叉编译的话方法是
CC=mips-unknown-linux-uclibc-gcc ./configure --host=mips-linux --disable-encodepass --disable-arp --disable-notify --disable-nls --with-pcap=libpcap.a
libpcap.a是mentohust需要的一个组件,我已经编译好放在文件夹里面了.
CC=mips-unknown-linux-uclibc-gcc 是指定交叉编译的工具链,我的交叉编译工具链的名字
就是这个,所以这么写,大家可以根据自己的交叉编译工具链进行更改.

#校园网外网认证
学校的校园网外网认证是安腾认证,就是大家俗称的红蝴蝶
aecium是安师大学长根据官方版本反汇编重写的
详细链接:[Amtium eFlow Client for GNU/Linux](http://www.anshida.net/bbs/thread-28476-1-1.html)
aecium支持赛尔、安腾以及友讯的BAS认证.

##外网认证 for linux

	aclocal
	autoheader
	automake --add-missing
	autoconf
	./configure --prefix=/usr
	make
	make install
解释:
	先用aclocal扫描configure.ac/.in生成aclocal.m4
	再用autoheader生成特定的C文件头
	再用automake扫描Makefile.am生成Makeifle.in
	再用autoconf根据configure.in生成configure
	configure根据Makefile.in生成最后的makefile

##外网认证 for mips
在路由器上完成外网认证我整整折腾了半个月(还是我太菜啊)
关键问题是路由器的CPU是大端字节序的 PC的CPU是下端字节序的
而认证的时候使用了MD5进行数据加密,MD5在不同类型的字节序加密
方式也会不一样.于是修改源码在md5.c文件第19行加一句#define WORDS_BIGENDIAN
问题变解决了,在此感谢给予我帮助的薛峰老师.
然后对代码其它地方进行小幅度的修改,使能适应路由器的busybox.
交叉编译的方法:

	aclocal
	autoheader
	automake --add-missing
	autoconf
	CC=mips-unknown-linux-uclibc-gcc ./configure --host=mips-linux
	make
至此,完成了校园网认证在Linux平台和路由器上的使用.能在路由器上认证校园网就再也不用
担心平板和手机上网的问题啦~希望这个项目能对大家有帮助,谢谢~

