/*
 * nf_udp_echo.h
 *
 *  Created on: Jul 21, 2015
 *      Author: Sergey Purik
 */

#ifndef NF_UDP_ECHO_H_
#define NF_UDP_ECHO_H_

#define NF_UDP_ECHO_MODULE_NAME "nf_udp_echo"

#define PROC_FS_NF_UDP_ECHO_DIR NF_UDP_ECHO_MODULE_NAME
#define PROC_FS_NF_UDP_POTRS "ports"
#define PROC_FS_NF_UDP_STATUS "status"

#ifdef __KERNEL__

#include <linux/types.h>
#define DEBUG_MODULE 1
#define UDP_ECHO_FEATURE_STATUS 1
#define UDP_ECHO_MAX_PORTS 128

void set_ports(const char * data);
size_t get_ports(char * buff, size_t buff_size);

#if UDP_ECHO_FEATURE_STATUS
void reset_status(void);
size_t get_status(char * buff, size_t buff_size);
#endif //UDP_ECHO_FEATURE_STATUS

int proc_fs_init(void);
void proc_fs_clear(void);

#endif /* __KERNEL__ */

#endif /* NF_UDP_ECHO_H_ */
