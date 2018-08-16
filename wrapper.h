#include<linux/if_tun.h>
#include<linux/ioctl.h>
#include<linux/sockios.h>
#include<net/if.h>
#include<stdint.h>

uint64_t CONST_TUNSETIFF    = TUNSETIFF;
uint64_t CONST_SIOCSIFFLAGS = SIOCSIFFLAGS;
