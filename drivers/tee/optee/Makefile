obj-$(CONFIG_OPTEE) += optee.o
optee-objs += core.o
optee-objs += call.o
ifdef CONFIG_ARM
plus_sec := $(call as-instr,.arch_extension sec,+sec)
AFLAGS_smc_a32.o := -Wa,-march=armv7-a$(plus_sec)
optee-objs += smc_a32.o
endif
ifdef CONFIG_ARM64
optee-objs += smc_a64.o
endif
optee-objs += rpc.o
optee-objs += supp.o
