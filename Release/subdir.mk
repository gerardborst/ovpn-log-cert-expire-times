################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../log-expire-warnings.c 

C_DEPS += \
./log-expire-warnings.d 

OBJS += \
./log-expire-warnings.o 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -DENABLE_CRYPTO=yes -DCOMPILE_TYPE=Release -DBUILD_TIME=$(BUILD_TIME) -DVERSION=$(VERSION_TAG) -DCOMMIT_HASH=$(COMMIT_HASH) -I/usr/include/openvpn -I/usr/include/openssl -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean--2e-

clean--2e-:
	-$(RM) ./log-expire-warnings.d ./log-expire-warnings.o

.PHONY: clean--2e-

