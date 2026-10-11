// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#ifndef ASTERISK_BPF_CGROUP_OWNED_H
#define ASTERISK_BPF_CGROUP_OWNED_H
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
struct asterisk_cgroup_program { const char *pin; const char *name; unsigned type; };
static const struct asterisk_cgroup_program asterisk_cgroup_programs[] = {
 {"cgroup_connect4","b2s_conn4",BPF_CGROUP_INET4_CONNECT},
 {"cgroup_sendmsg4","b2s_udp4",BPF_CGROUP_UDP4_SENDMSG},
 {"cgroup_recvmsg4","b2s_urcv4",BPF_CGROUP_UDP4_RECVMSG},
 {"cgroup_connect6","b2s_conn6",BPF_CGROUP_INET6_CONNECT},
 {"cgroup_sendmsg6","b2s_udp6",BPF_CGROUP_UDP6_SENDMSG},
 {"cgroup_recvmsg6","b2s_urcv6",BPF_CGROUP_UDP6_RECVMSG},
 {"cgroup_connect6_mapped","b2s_c6v4m",BPF_CGROUP_INET6_CONNECT},
 {"cgroup_sendmsg6_mapped","b2s_u6v4m",BPF_CGROUP_UDP6_SENDMSG},
 {"cgroup_recvmsg6_mapped","b2s_ur6v4m",BPF_CGROUP_UDP6_RECVMSG},
 {"cgroup_peer_cap4","b2s_ppeer4",BPF_CGROUP_INET4_GETPEERNAME},
 {"cgroup_peer_cap6","b2s_ppeer6",BPF_CGROUP_INET6_GETPEERNAME},
 {"cgroup_peer4","b2s_upeer4",BPF_CGROUP_INET4_GETPEERNAME},
 {"cgroup_peer6","b2s_upeer6",BPF_CGROUP_INET6_GETPEERNAME},
};
static inline int asterisk_cgroup_sys(enum bpf_cmd command, union bpf_attr *attr) {
 return (int)syscall(__NR_bpf,command,attr,sizeof(*attr));
}
static inline int asterisk_cgroup_info(int fd,struct bpf_prog_info *info) {
 union bpf_attr a;memset(&a,0,sizeof(a));memset(info,0,sizeof(*info));
 a.info.bpf_fd=(uint32_t)fd;a.info.info_len=sizeof(*info);a.info.info=(uintptr_t)info;
 return asterisk_cgroup_sys(BPF_OBJ_GET_INFO_BY_FD,&a);
}
static inline int asterisk_cgroup_path(char *out,size_t size,const char *root,const char *name) {
 int n=snprintf(out,size,"%s/%s",root,name);if(n<0 || (size_t)n>=size){errno=ENAMETOOLONG;return -1;}return 0;
}
/* Pin before attach, so abrupt helper death cannot destroy cleanup authority.
 * Never overwrite a pin: the supervisor reconciles the fixed catalog first. */
static inline int asterisk_cgroup_pin(int fd,const char *root) {
 struct bpf_prog_info info; if(asterisk_cgroup_info(fd,&info))return -1;
 for(size_t i=0;i<sizeof(asterisk_cgroup_programs)/sizeof(asterisk_cgroup_programs[0]);i++) {
  const struct asterisk_cgroup_program *p=&asterisk_cgroup_programs[i];
  if(info.type!=BPF_PROG_TYPE_CGROUP_SOCK_ADDR || strcmp(info.name,p->name))continue;
  char path[512];if(asterisk_cgroup_path(path,sizeof(path),root,p->pin))return -1;
  union bpf_attr a;memset(&a,0,sizeof(a));a.pathname=(uintptr_t)path;a.bpf_fd=(uint32_t)fd;
  return asterisk_cgroup_sys(BPF_OBJ_PIN,&a);
 }
 errno=EINVAL;return -1;
}
static inline int asterisk_cgroup_has_id(int cgroup,unsigned type,uint32_t id) {
 uint32_t ids[64];union bpf_attr a;memset(&a,0,sizeof(a));
 a.query.target_fd=(uint32_t)cgroup;a.query.attach_type=type;a.query.prog_cnt=64;a.query.prog_ids=(uintptr_t)ids;
 if(asterisk_cgroup_sys(BPF_PROG_QUERY,&a))return -1;
 if(a.query.prog_cnt>64){errno=E2BIG;return -1;}
 for(uint32_t i=0;i<a.query.prog_cnt;i++)if(ids[i]==id) {
  /* Exclusive detach may ignore the program FD. Never use that operation. */
  if(a.query.attach_flags!=BPF_F_ALLOW_MULTI){errno=EPERM;return -1;}
  return 1;
 }
 return 0;
}
/* Only the object opened from the fixed pin is authority. Names alone, program
 * enumeration, saved config and telemetry never grant ownership. Keep every
 * pin on error so the next listener owner can retry exact detach. */
static inline int asterisk_cgroup_detach_pins(const char *cgroup_path,const char *root) {
 int cg=-1,result=0;
 for(size_t i=0;i<sizeof(asterisk_cgroup_programs)/sizeof(asterisk_cgroup_programs[0]);i++) {
  const struct asterisk_cgroup_program *p=&asterisk_cgroup_programs[i];char path[512];
  if(asterisk_cgroup_path(path,sizeof(path),root,p->pin)){result=-1;break;}
  union bpf_attr a;memset(&a,0,sizeof(a));a.pathname=(uintptr_t)path;
  int fd=asterisk_cgroup_sys(BPF_OBJ_GET,&a);
  if(fd<0){if(errno==ENOENT)continue;result=-1;break;}
  struct bpf_prog_info info;
  if(asterisk_cgroup_info(fd,&info) || info.id==0 || info.type!=BPF_PROG_TYPE_CGROUP_SOCK_ADDR ||
     memcmp(info.name,p->name,strlen(p->name)+1)!=0) {close(fd);errno=ESTALE;result=-1;break;}
  if(cg<0)cg=open(cgroup_path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
  if(cg<0){close(fd);result=-1;break;}
  int attached=asterisk_cgroup_has_id(cg,p->type,info.id);
  if(attached>0) {
   memset(&a,0,sizeof(a));a.target_fd=(uint32_t)cg;a.attach_bpf_fd=(uint32_t)fd;a.attach_type=p->type;
   if(asterisk_cgroup_sys(BPF_PROG_DETACH,&a))attached=-1;
   else attached=asterisk_cgroup_has_id(cg,p->type,info.id);
  }
  close(fd);
  if(attached!=0){result=-1;break;}
 }
 if(cg>=0)close(cg);
 return result;
}
static inline int asterisk_cgroup_reconcile(const char *cgroup_path,const char *root) {
 if(asterisk_cgroup_detach_pins(cgroup_path,root))return -1;
 for(size_t i=0;i<sizeof(asterisk_cgroup_programs)/sizeof(asterisk_cgroup_programs[0]);i++) {
  char path[512];if(asterisk_cgroup_path(path,sizeof(path),root,asterisk_cgroup_programs[i].pin))return -1;
  if(unlink(path) && errno!=ENOENT)return -1;
 }
 return 0;
}
#endif
