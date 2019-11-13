# NAME		:= execmon
NAME		:= crashessome
obj-m		:= $(NAME).o
obj-y 		:= libudis86/
# KERNEL_DIR	?= /lib/modules/$(shell uname -r)/build
KERNEL_DIR	?= /lib/modules/3.10.0-693.el7.x86_64/build

$(NAME)-y	:= main.o mem.o syscalls.o comm.o proto.o  \
			libudis86/built-in.o

all:
	make -C $(KERNEL_DIR) M=$(shell pwd)
	cp $(NAME).ko ../$(NAME).ko
clean:
	# make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	make -C $(KERNEL_DIR) M=$(PWD) clean

