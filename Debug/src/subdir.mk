################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../src/logtest.o 

C_SRCS += \
../src/ae.c \
../src/ae_interfaces.c \
../src/logtest.c 

OBJS += \
./src/ae.o \
./src/ae_interfaces.o \
./src/logtest.o 

C_DEPS += \
./src/ae.d \
./src/ae_interfaces.d \
./src/logtest.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I/usr/local/openssl/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


