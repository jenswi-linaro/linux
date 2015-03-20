EXTRA_CFLAGS += -O0

obj-$(CONFIG_OPTEE) += optee.o
optee-objs += core.o
ifdef CONFIG_ARM
optee-objs += smc_a32.o
endif
ifdef CONFIG_ARM64
optee-objs += smc_a64.o
endif
optee-objs += rpc.o
optee-objs += supp.o
