.PHONY : default clean distclean

TARGET = nf_udp_echo

# result object file 
obj-m += $(TARGET).o 

# multiply sources
$(TARGET)-objs := \
nf_udp_echo_main.o \
nf_udp_echo_proc_fs.o

ccflags-y := -std=gnu99 -Wno-declaration-after-statement

PWD = $(shell pwd)
KDIR = /lib/modules/$(shell uname -r)/build

default:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	#$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order
	@rm -f .*.*.cmd *.symvers *~ *.*~ TODO.*
	@rm -fR .tmp*
	@rm -rf .tmp_versions

distclean: clean
	@rm -f *.ko

