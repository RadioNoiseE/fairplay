#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define WARNING(...) console ("warning", __VA_ARGS__)

#define ERROR(...)                        \
  do {                                    \
    console ("fatal error", __VA_ARGS__); \
    _exit (1);                            \
  } while (0)

static inline uint32_t bswap32 (uint32_t value) {
  return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) |
         ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24);
}

void console (const char *key, const char *value, ...) {
  char    msg[4096];
  va_list fmt;

  va_start (fmt, value);
  vsnprintf (msg, sizeof (msg), value, fmt);
  syslog (LOG_NOTICE, "%-*s%s", 14, key, msg);
  va_end (fmt);
}

void decrypt (const char *path, const struct mach_header *mh) {
  int      in_fd, out_fd;
  long     pos_tmp;
  char     buffer[4096], in_path[4096], out_path[4096], *str_tmp;
  off_t    off_cid, off_rest, off_read;
  uint32_t off_tmp = 0, int_tmp = 0, zero = 0;

  struct fat_arch                *fa;
  struct fat_header              *fh;
  struct load_command            *lc;
  struct encryption_info_command *eic;

  if (realpath (path, in_path) == NULL)
    strlcpy (in_path, path, sizeof (in_path));

  str_tmp = strrchr (in_path, '/');
  if (str_tmp == NULL)
    ERROR ("wierd path %s", in_path);
  else
    console ("target", "%s", str_tmp + 1);

  switch (mh->magic) {
  case MH_MAGIC:
    lc = (struct load_command *) ((unsigned char *) mh +
                                  sizeof (struct mach_header));
    console ("magic number", "32-bit");
    break;
  case MH_MAGIC_64:
    lc = (struct load_command *) ((unsigned char *) mh +
                                  sizeof (struct mach_header_64));
    console ("magic number", "64-bit");
    break;
  default:
    ERROR ("unknown header %x", mh->magic);
  }

  for (int i = 0; i < mh->ncmds; i++) {
    if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
      eic = (struct encryption_info_command *) lc;

      if (eic->cryptid == 0) {
        WARNING ("nothing was decrypted");
        break;
      }

      off_cid = ((unsigned char *) &eic->cryptid - (unsigned char *) mh);
      console ("cryptid offset", "%x", off_cid);

      in_fd = open (in_path, O_RDONLY);
      if (in_fd == -1)
        ERROR ("failed opening file %s", in_path);

      int_tmp = read (in_fd, (void *) buffer, sizeof (buffer));
      if (int_tmp != sizeof (buffer))
        WARNING ("only %d bytes being read", int_tmp);
      fh = (struct fat_header *) buffer;

      switch (fh->magic) {
      case FAT_CIGAM:
        console ("image type", "fat image");
        fa = (struct fat_arch *) (fh + 1);
        for (int i = 0; i < bswap32 (fh->nfat_arch); i++, fa++) {
          if (mh->cputype == bswap32 (fa->cputype) &&
              mh->cpusubtype == bswap32 (fa->cpusubtype)) {
            off_tmp = bswap32 (fa->offset);
            console ("arch offset", "%x", off_tmp);
            break;
          }
        }
        if (off_tmp == 0)
          ERROR ("failed finding correct arch");
        break;
      case MH_MAGIC:
      case MH_MAGIC_64:
        console ("image type", "mach object");
        break;
      default:
        ERROR ("unknown type of executable");
      }

      strlcpy (out_path, str_tmp + 1, sizeof (out_path));
      strlcat (out_path, ".d", sizeof (out_path));

      out_fd = open (out_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
      if (out_fd == -1)
        ERROR ("failed opening file %s", out_path);

      int_tmp  = off_tmp + eic->cryptoff;
      off_rest = lseek (in_fd, 0, SEEK_END) - int_tmp - eic->cryptsize;
      lseek (in_fd, 0, SEEK_SET);

      console ("copying", "not encrypted header");
      while (int_tmp > 0) {
        off_read = int_tmp > sizeof (buffer) ? sizeof (buffer) : int_tmp;
        pos_tmp  = read (in_fd, buffer, off_read);
        if (pos_tmp != off_read)
          ERROR ("failed reading file");

        pos_tmp = write (out_fd, buffer, off_read);
        if (pos_tmp != off_read)
          ERROR ("failed writing file");

        int_tmp -= off_read;
      }

      console ("dumping", "decrypted memory");
      pos_tmp =
          write (out_fd, (unsigned char *) mh + eic->cryptoff, eic->cryptsize);
      if (pos_tmp != eic->cryptsize)
        ERROR ("failed writing file");

      int_tmp = off_read;
      lseek (in_fd, eic->cryptsize, SEEK_CUR);

      console ("copying", "not encrypted remainder");
      while (int_tmp > 0) {
        off_read = int_tmp > sizeof (buffer) ? sizeof (buffer) : int_tmp;
        pos_tmp  = read (in_fd, buffer, off_read);
        if (pos_tmp != off_read)
          ERROR ("failed reading file");

        pos_tmp = write (out_fd, buffer, off_read);
        if (pos_tmp != off_read)
          ERROR ("failed writing file");

        int_tmp -= off_read;
      }

      if (off_cid) {
        off_cid += off_tmp;
        console ("modify", "cryptid at offset %x", off_cid);
        if (lseek (out_fd, off_cid, SEEK_SET) != off_cid ||
            write (out_fd, &zero, 4) != 4)
          ERROR ("failed overwriting encryption status");
      }

      console ("terminate", "closing file handlers");
      close (in_fd);
      close (out_fd);
    }

    lc = (struct load_command *) ((unsigned char *) lc + lc->cmdsize);
  }
}

static void queue (const struct mach_header *mh, intptr_t slide) {
  Dl_info ii;
  dladdr (mh, &ii);
  decrypt (ii.dli_fname, mh);
}

__attribute__ ((constructor)) static void dump () {
  printf ("decrypting Mach-O image encrypted by FairPlay DRM...\n");
  _dyld_register_func_for_add_image (&queue);
}
