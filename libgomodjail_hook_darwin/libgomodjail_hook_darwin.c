/* TODO: split to multiple files */
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define STR_EQ(x, y) ((x) != NULL && (y) != NULL && strcmp((x), (y)) == 0)
#define STR_HAS_PREFIX(x, y)                                                   \
  ((x) != NULL && (y) != NULL && strncmp((x), (y), strlen(y)) == 0)

#ifdef DEBUG
static bool debug = true;
#else
static bool debug = false;
#endif

#define ERRORF(fmt, ...)                                                       \
  fprintf(stderr, "GOMODJAIL::ERROR| " fmt "\n", ##__VA_ARGS__);

#define WARNF(fmt, ...)                                                        \
  fprintf(stderr, "GOMODJAIL::WARN | " fmt "\n", ##__VA_ARGS__);

#define DEBUGF(fmt, ...)                                                       \
  do {                                                                         \
    if (debug)                                                                 \
      fprintf(stderr, "GOMODJAIL::DEBUG| " fmt "\n", ##__VA_ARGS__);           \
  } while (0)

static bool enabled = false;

/* TODO: move to go_runtime_info */
static char exe_path[MAXPATHLEN];
static uint32_t exe_path_len = MAXPATHLEN;

struct go_runtime_offset {
  char *version_prefix;
  off_t g_m;
  off_t m_libcallpc;
  off_t m_libcallsp;
};

static struct go_runtime_offset go_runtime_offsets[] = {
    /* When updating the list, update README.md too */
    {
        /* go1.25 */
        .version_prefix = "go1.25",
        .g_m = 48,
        .m_libcallpc = 872,
        .m_libcallsp = 880,
    },

    {
        /* go1.24.0 */
        .version_prefix = "go1.24",
        .g_m = 48,
        .m_libcallpc = 856,
        .m_libcallsp = 864,
    },
    {
        /* go1.23.6 */
        .version_prefix = "go1.23",
        .g_m = 48,
        .m_libcallpc = 832,
        .m_libcallsp = 840,
    },
    {
        /* go1.22.12 */
        .version_prefix = "go1.22",
        .g_m = 48,
        .m_libcallpc = 1048,
        .m_libcallsp = 1056,
    },
    {
        .version_prefix = NULL,
        .g_m = 0,
        .m_libcallpc = 0,
        .m_libcallsp = 0,
    },
};

/* TODO: move to go_runtime_info */
static struct go_runtime_offset *go_runtime_offset_current = NULL;

struct go_runtime_info {
  char *version; /* *NOT* freeable */
  uint64_t *tls_g_addr;
};

static struct go_runtime_info go_runtime_info;

// The result is *NOT* freeable.
static char *get_go_version_from_go_buildinfo_buf(uint8_t *buf) {
  char *res = NULL;
  if (memcmp(buf, "\xff Go buildinf:", 14) != 0) {
    ERRORF("expected __go_buildinfo to have a valid magic");
    goto done;
  }
  if (buf[14] != 8) {
    ERRORF("expected __go_buildinfo[14] (pointer size) to be 8, got %d",
           buf[14]);
    goto done;
  }
  if (buf[15] != 2) {
    ERRORF("expected __go_buildinfo[15] (endianness) to be 2, got %d", buf[15]);
    goto done;
  }
  uint8_t varint0 = buf[32];
  if ((varint0 & 0x80) != 0) {
    ERRORF("expected __go_buildinfo[32] (varint of go version length) not to "
           "have the continuation bit, got %d",
           varint0);
    goto done;
  }
  static char res_buf[128];
  memcpy(res_buf, buf + 33, varint0);
  res = res_buf;
done:
  return res;
}

static struct go_runtime_info get_go_runtime_info_from_file_buf(void *buf) {
  struct go_runtime_info res;
  memset(&res, 0, sizeof(res));
  struct mach_header_64 *mh = (struct mach_header_64 *)buf;
  if (mh->magic != MH_MAGIC_64) {
    /* TODO: support FAT_MAGIC? */
    ERRORF("expected MH_MAGIC_64, got %d", mh->magic);
    goto done;
  }
  struct load_command *lc = (struct load_command *)(buf + sizeof(*mh));
  uint32_t i;
  for (i = 0; i < mh->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT_64) {
      struct segment_command_64 *seg = (struct segment_command_64 *)lc;
      struct section_64 *sect =
          (struct section_64 *)((uint8_t *)seg + sizeof(*seg));
      for (uint32_t s = 0; s < seg->nsects; s++) {
        if (strncmp(sect[s].sectname, "__go_buildinfo", 14) == 0) {
          res.version =
              get_go_version_from_go_buildinfo_buf(buf + sect[s].offset);
        }
      }
    } else if (lc->cmd == LC_SYMTAB) {
      struct symtab_command *stcmd = (struct symtab_command *)lc;
      char *strtab = (char *)buf + stcmd->stroff;
      struct nlist_64 *symtab =
          (struct nlist_64 *)((uint8_t *)buf + stcmd->symoff);
      for (uint32_t j = 0; j < stcmd->nsyms; j++) {
        char *name = strtab + symtab[j].n_un.n_strx;
        if (STR_EQ(name, "_runtime.tls_g")) {
          int image_index = 1; /* FIXME: parse */
          uint64_t runtime_tls_g_sym_value = (uint64_t)symtab[j].n_value;
          res.tls_g_addr =
              (uint64_t *)(_dyld_get_image_vmaddr_slide(image_index) +
                           runtime_tls_g_sym_value);
        }
      }
    }
    lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
  }
done:
  return res;
}

static struct go_runtime_info get_go_runtime_info_from_file(const char *path) {
  struct go_runtime_info res;
  memset(&res, 0, sizeof(res));
  void *mm = NULL;
  size_t mm_len = -1;
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    ERRORF("open(\"%s\") failed: %s", path, strerror(errno));
    goto done;
  }
  struct stat st;
  if (fstat(fd, &st) < 0) {
    ERRORF("fstat(\"%s\") failed: %s", path, strerror(errno));
    goto done;
  }
  mm_len = (size_t)st.st_size;
  mm = mmap(NULL, mm_len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mm == NULL) {
    ERRORF("mmap failed: %s", strerror(errno));
    goto done;
  }
  close(fd);
  fd = -1;
  res = get_go_runtime_info_from_file_buf(mm);
done:
  if (fd >= 0)
    close(fd);
  if (mm != NULL)
    munmap(mm, mm_len);
  return res;
}

static void init() __attribute__((constructor));

static uint64_t (*runtime_load_g)(void) = NULL;

static void init() {
  debug = getenv("DEBUG") != NULL;
  if (_NSGetExecutablePath(exe_path, &exe_path_len) != 0) {
    ERRORF("_NSGetExecutablePath() failed");
    return;
  }
  go_runtime_info = get_go_runtime_info_from_file(exe_path);
  char *go_version = go_runtime_info.version; /* Not freeable */
  if (!go_version) {
    WARNF("%s: Not a Go binary. Ignoring.", exe_path);
    return;
  }
  DEBUGF("%s: Go version=\"%s\"", exe_path, go_version);
  for (int i = 0; go_runtime_offsets[i].version_prefix; i++) {
    if (STR_HAS_PREFIX(go_version, go_runtime_offsets[i].version_prefix)) {
      DEBUGF("%s: treating Go version \"%s\" as %s", exe_path, go_version,
             go_runtime_offsets[i].version_prefix);
      DEBUGF("%s: Go runtime offsets: g->m: %lld, m->libcallpc: %lld, "
             "m->libcallsp: %lld",
             exe_path, go_runtime_offsets[i].g_m,
             go_runtime_offsets[i].m_libcallpc,
             go_runtime_offsets[i].m_libcallsp);
      go_runtime_offset_current = &go_runtime_offsets[i];
      break;
    }
  }
  if (!go_runtime_offset_current) {
    ERRORF("%s: Unsupported Go version: \"%s\"", exe_path, go_version);
    return;
  }
  if (!go_runtime_info.tls_g_addr) { /* stripped binary */
#ifdef __aarch64__
    const char *load_g_str = getenv("LIBGOMODJAIL_HOOK_LOAD_G_ADDR");
    if (!load_g_str) {
      ERRORF("%s: _runtime.tls_g not found, and LIBGOMODJAIL_HOOK_LOAD_G_ADDR is unset",
             exe_path);
      return;
    }
    char *endptr;
    uint64_t load_g = strtoull(load_g_str, &endptr, 10);
    if (endptr == load_g_str || *endptr != '\0' || load_g == 0) {
      ERRORF("%s: failed to parse LIBGOMODJAIL_HOOK_LOAD_G_ADDR=%s", exe_path,
             load_g_str);
      return;
    }
    DEBUGF("%s: using runtime_load_g at %lld", exe_path, load_g);
    runtime_load_g = (uint64_t (*)(void))load_g;
    const int image_index = 1; /* FIXME: parse */
    runtime_load_g = _dyld_get_image_vmaddr_slide(image_index) + (void *)load_g;
#endif
  }
  enabled = true;
}

#if defined(__aarch64__)
static uint64_t fetch_g() {
  uintptr_t tls_base;
  __asm__ __volatile__("mrs %0, tpidrro_el0" : "=r"(tls_base));
  tls_base &= ~((uintptr_t)7);
  uint64_t runtime_tls_g;
  if (go_runtime_info.tls_g_addr) {
    runtime_tls_g = *go_runtime_info.tls_g_addr;
  } else if (runtime_load_g){
    runtime_load_g();
    // Discard the ret value R0, read R27
    // https://github.com/golang/go/blob/go1.25.3/src/runtime/tls_arm64.s#L11-L30
  __asm__ __volatile__("mov %0, x27" : "=r"(runtime_tls_g));
  } else {
    ERRORF("!go_runtime_info.tls_g_addr && !runtime_load_g");
    return 0;
  }
  uint64_t g = *(uint64_t *)(tls_base + runtime_tls_g);
  return g;
}
#define BP_ADJUSTMENT 8
#elif defined(__x86_64__)
static uint64_t fetch_g() {
  uintptr_t g;
  /* https://github.com/golang/go/issues/23617 */
  __asm__ __volatile__("movq %%gs:0x30, %0" : "=r"(g));
  return g;
}
#define BP_ADJUSTMENT 16
#endif

/* Returns true if execution is allowed */
static bool handle_syscall(const char *syscall_name) {
  bool res = true;
  int sock = -1;
  char *json_buf = NULL;
  size_t json_len = -1;
  FILE *json_fp = NULL;

  if (!enabled) {
    DEBUGF("Handler is not enabled");
    goto done;
  }

  if (!go_runtime_offset_current) {
    DEBUGF("Go runtime is not recognized");
    goto done;
  }

  {
    struct sockaddr_un addr;
    char *sock_path = getenv("LIBGOMODJAIL_HOOK_SOCKET");
    if (sock_path == NULL) {
      ERRORF("LIBGOMODJAIL_HOOK_SOCKET is unset");
      goto done;
    }
    if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
      ERRORF("socket() failed: %s", strerror(errno));
      goto done;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = PF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      ERRORF("connect() failed: %s", strerror(errno));
      goto done;
    }
  }

  if ((json_fp = open_memstream(&json_buf, &json_len)) == NULL) {
    ERRORF("open_memstream() failed: %s", strerror(errno));
    goto done;
  }

  fprintf(json_fp, "{\"pid\":%d,\"exe\":\"%s\",\"syscall\":\"%s\",\"stack\":[",
          getpid(), exe_path, syscall_name);

  {
    int image_index = 1; /* FIXME: parse */
    intptr_t slide = _dyld_get_image_vmaddr_slide(image_index);
    void *callstack[128];
    int frames = backtrace(callstack, sizeof(callstack) / sizeof(callstack[0]));
    for (int i = 0; i < frames; ++i) {
      Dl_info dli;
      if (dladdr(callstack[i], &dli) > 0) {
        DEBUGF("* %s\t%s", dli.dli_fname, dli.dli_sname);
        fprintf(json_fp, "{\"file\":\"%s\",\"symbol\":\"%s\"},", dli.dli_fname,
                dli.dli_sname);
        if ((dli.dli_sname == NULL && runtime_load_g) || STR_EQ(dli.dli_sname, "runtime.asmcgocall.abi0")) {
          uint64_t g_addr = fetch_g();
          if (!g_addr) {
            ERRORF("!g_addr");
            break;
          }
          uint64_t m_addr_addr = g_addr + go_runtime_offset_current->g_m;
          uint64_t m_addr = *(uint64_t *)m_addr_addr;
          if (!m_addr) {
            ERRORF("!m_addr");
            break;
          }
          uint64_t libcallpc_addr =
              m_addr + go_runtime_offset_current->m_libcallpc;
          uint64_t libcallsp_addr =
              m_addr + go_runtime_offset_current->m_libcallsp;
          uint64_t pc = *(uint64_t *)libcallpc_addr;
          uint64_t sp = *(uint64_t *)libcallsp_addr;
          if (sp) {
            uint64_t bp = sp - BP_ADJUSTMENT;
            while (bp != 0) {
              uint64_t saved_bp = *(uint64_t *)bp;
              uint64_t ret_addr = *(uint64_t *)(bp + 8);
              Dl_info dli2;
              if (dladdr((void *)pc, &dli2) > 0) {
                DEBUGF("* %s\t%s", dli2.dli_fname, dli2.dli_sname);
                if (dli2.dli_sname == NULL) {
                  uint64_t addr_in_image = pc - slide;
                  fprintf(json_fp, "{\"address\":%lld},", addr_in_image);
                } else {
                  fprintf(json_fp, "{\"file\":\"%s\",\"symbol\":\"%s\"},",
                          dli2.dli_fname, dli2.dli_sname);
                }
              }
              pc = ret_addr;
              bp = saved_bp;
            }
          }
        }
      } else {
        DEBUGF("* %p", callstack[i]);
        uint64_t addr_in_image = (uint64_t)callstack[i] - (uint64_t)slide;
        fprintf(json_fp, "{\"address\":%lld},", addr_in_image);
      }
    }
  }

  /* A terminator entry is added to simplify the trailing comma logic */
  fprintf(json_fp, "{}]}");
  fclose(json_fp);
  json_fp = NULL;

  {
    uint32_t json_len32 = (uint32_t)json_len;
    if (write(sock, &json_len32, sizeof(json_len32)) < 0) {
      ERRORF("write() failed: %s", strerror(errno));
      goto done;
    }
    if (write(sock, json_buf, json_len) < 0) {
      ERRORF("write() failed: %s", strerror(errno));
      goto done;
    }
  }

  {
    uint8_t resp[5];
    if (read(sock, resp, sizeof(resp)) < 0) {
      ERRORF("read() failed: %s", strerror(errno));
      goto done;
    }
    /* TODO: parse JSON */
    res = resp[4] != '0';
  }
done:
  if (sock >= 0)
    close(sock);
  if (json_fp != NULL)
    fclose(json_fp);
  if (json_buf != NULL)
    free(json_buf);
  return res;
}

#define INTERPOSE(fn, hook)                                                    \
  __attribute__((                                                              \
      used, section("__DATA,__interpose"))) static void *interpose_##fn[] = {  \
      hook, fn}

static int open_needs_mode(int flags) { return flags & O_CREAT; }

#define HOOK_OPEN(func, args, call_no_mode, call_mode, fmt, ...)               \
  static int gmj_##func args {                                                 \
    DEBUGF(fmt, __VA_ARGS__);                                                  \
    if (handle_syscall(#func)) {                                               \
      if (open_needs_mode(flags)) {                                            \
        va_list ap;                                                            \
        va_start(ap, flags);                                                   \
        int mode = va_arg(ap, int);                                            \
        va_end(ap);                                                            \
        return call_mode;                                                      \
      }                                                                        \
      return call_no_mode;                                                     \
    }                                                                          \
    errno = EPERM;                                                             \
    return -1;                                                                 \
  }                                                                            \
  INTERPOSE(func, gmj_##func)

#define HOOK(func, signature, args, fmt, ...)                                  \
  static int gmj_##func signature {                                            \
    DEBUGF(fmt, __VA_ARGS__);                                                  \
    if (handle_syscall(#func)) {                                               \
      return func args;                                                        \
    }                                                                          \
    errno = EPERM;                                                             \
    return -1;                                                                 \
  }                                                                            \
  INTERPOSE(func, gmj_##func)

#define HOOK_SIMPLE(func, signature, args)                                     \
  HOOK(func, signature, args, "%s(...)", #func)

/* Files */
HOOK_OPEN(open, (const char *path, int flags, ...), open(path, flags),
          open(path, flags, mode), "open(\"%s\", 0x%x, ...)", path, flags);

HOOK_OPEN(openat, (int dirfd, const char *path, int flags, ...),
          openat(dirfd, path, flags), openat(dirfd, path, flags, mode),
          "openat(%d, \"%s\", 0x%x, ...)", dirfd, path, flags);

HOOK(creat, (const char *path, mode_t mode), (path, mode),
     "creat(\"%s\", 0o%o)", path, mode);

HOOK_SIMPLE(exchangedata,
            (const char *path1, const char *path2, unsigned int options),
            (path1, path2, options));

HOOK_SIMPLE(chmod, (const char *path, mode_t mode), (path, mode));
HOOK_SIMPLE(fchmod, (int fildes, mode_t mode), (fildes, mode));
HOOK_SIMPLE(fchmodat, (int fd, const char *path, mode_t mode, int flag),
            (fd, path, mode, flag));
HOOK_SIMPLE(chown, (const char *path, uid_t owner, gid_t group),
            (path, owner, group));
HOOK_SIMPLE(fchown, (int fildes, uid_t owner, gid_t group),
            (fildes, owner, group));
HOOK_SIMPLE(lchown, (const char *path, uid_t owner, gid_t group),
            (path, owner, group));
HOOK_SIMPLE(fchownat,
            (int fd, const char *path, uid_t owner, gid_t group, int flag),
            (fd, path, owner, group, flag));
HOOK_SIMPLE(link, (const char *path1, const char *path2), (path1, path2));
HOOK_SIMPLE(linkat,
            (int fd1, const char *name1, int fd2, const char *name2, int flag),
            (fd1, name1, fd2, name2, flag));
HOOK_SIMPLE(mkdir, (const char *path, mode_t mode), (path, mode));
HOOK_SIMPLE(mkdirat, (int fd, const char *path, mode_t mode), (fd, path, mode));
HOOK_SIMPLE(mknod, (const char *path, mode_t mode, dev_t dev),
            (path, mode, dev));
HOOK_SIMPLE(mknodat, (int fd, const char *path, mode_t mode, dev_t dev),
            (fd, path, mode, dev));
HOOK_SIMPLE(unlink, (const char *path), (path));
HOOK_SIMPLE(unlinkat, (int fd, const char *path, int flag), (fd, path, flag));
HOOK_SIMPLE(undelete, (const char *path), (path));

/* Sockets */
HOOK_SIMPLE(listen, (int socket, int backlog), (socket, backlog));
HOOK_SIMPLE(connect,
            (int socket, const struct sockaddr *address, socklen_t address_len),
            (socket, address, address_len));

/* Processes */
HOOK(execve, (const char *path, char *const argv[], char *const envp[]),
     (path, argv, envp), "execve(\"%s\", ...)", path);
HOOK_SIMPLE(posix_spawn,
            (pid_t *restrict pid, const char *restrict path,
             const posix_spawn_file_actions_t *file_actions,
             const posix_spawnattr_t *restrict attrp,
             char *const argv[restrict], char *const envp[restrict]),
            (pid, path, file_actions, attrp, argv, envp));
HOOK_SIMPLE(posix_spawnp,
            (pid_t *restrict pid, const char *restrict file,
             const posix_spawn_file_actions_t *file_actions,
             const posix_spawnattr_t *restrict attrp,
             char *const argv[restrict], char *const envp[restrict]),
            (pid, file, file_actions, attrp, argv, envp));
