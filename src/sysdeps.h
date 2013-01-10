/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* this file contains system-dependent definitions used by SDB
 * they're related to threads, sockets and file descriptors
 */
#ifndef _SDB_SYSDEPS_H
#define _SDB_SYSDEPS_H

#ifdef __CYGWIN__
#  undef _WIN32
#endif

#ifdef _WIN32

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#define OS_PATH_SEPARATOR '\\'
#define OS_PATH_SEPARATOR_STR "\\"

typedef CRITICAL_SECTION          sdb_mutex_t;

#define  SDB_MUTEX_DEFINE(x)     sdb_mutex_t   x

/* declare all mutexes */
/* For win32, sdb_sysdeps_init() will do the mutex runtime initialization. */
#define  SDB_MUTEX(x)   extern sdb_mutex_t  x;
#include "mutex_list.h"

extern void  sdb_sysdeps_init(void);

static __inline__ char* ansi_to_utf8(const char *str)
{
    int len;
    char *utf8;
    wchar_t *unicode;

    //ANSI( MutiByte ) -> UCS-2( WideByte ) -> UTF-8( MultiByte )
    len = MultiByteToWideChar (CP_ACP, 0, str, -1, NULL, 0);
    unicode = (wchar_t *)calloc (len+1, sizeof(wchar_t));
    MultiByteToWideChar (CP_ACP, 0, str, -1, unicode, len);

    len = WideCharToMultiByte (CP_UTF8, 0, unicode, -1, NULL, 0, NULL, NULL);
    utf8 = (char *)calloc (len+1, sizeof(char));

    WideCharToMultiByte (CP_UTF8, 0, unicode, -1, utf8, len, NULL, NULL);
    free (unicode);

    return utf8;
}

static __inline__ void sdb_mutex_lock( sdb_mutex_t*  lock )
{
    EnterCriticalSection( lock );
}

static __inline__ void  sdb_mutex_unlock( sdb_mutex_t*  lock )
{
    LeaveCriticalSection( lock );
}

typedef struct { unsigned  tid; }  sdb_thread_t;

typedef  void*  (*sdb_thread_func_t)(void*  arg);

typedef  void (*win_thread_func_t)(void*  arg);

static __inline__ int  sdb_thread_create( sdb_thread_t  *thread, sdb_thread_func_t  func, void*  arg)
{
    thread->tid = _beginthread( (win_thread_func_t)func, 0, arg );
    if (thread->tid == (unsigned)-1L) {
        return -1;
    }
    return 0;
}

static __inline__ void  close_on_exec(int  fd)
{
    /* nothing really */
}

extern void  disable_tcp_nagle(int  fd);

#define  lstat    stat   /* no symlinks on Win32 */

#define  S_ISLNK(m)   0   /* no symlinks on Win32 */

static __inline__  int    sdb_unlink(const char*  path)
{
    int  rc = unlink(path);

    if (rc == -1 && errno == EACCES) {
        /* unlink returns EACCES when the file is read-only, so we first */
        /* try to make it writable, then unlink again...                  */
        rc = chmod(path, _S_IREAD|_S_IWRITE );
        if (rc == 0)
            rc = unlink(path);
    }
    return rc;
}
#undef  unlink
#define unlink  ___xxx_unlink

static __inline__ int  sdb_mkdir(const char*  path, int mode)
{
    return _mkdir(path);
}
#undef   mkdir
#define  mkdir  ___xxx_mkdir

extern int  sdb_open(const char*  path, int  options);
extern int  sdb_creat(const char*  path, int  mode);
extern int  sdb_read(int  fd, void* buf, int len);
extern int  sdb_write(int  fd, const void*  buf, int  len);
extern int  sdb_lseek(int  fd, int  pos, int  where);
extern int  sdb_shutdown(int  fd);
extern int  sdb_close(int  fd);

static __inline__ int  unix_close(int fd)
{
    return close(fd);
}
#undef   close
#define  close   ____xxx_close

static __inline__  int  unix_read(int  fd, void*  buf, size_t  len)
{
    return read(fd, buf, len);
}
#undef   read
#define  read  ___xxx_read

static __inline__  int  unix_write(int  fd, const void*  buf, size_t  len)
{
    return write(fd, buf, len);
}
#undef   write
#define  write  ___xxx_write

static __inline__ int  sdb_open_mode(const char* path, int options, int mode)
{
    return sdb_open(path, options);
}

static __inline__ int  unix_open(const char*  path, int options,...)
{
    if ((options & O_CREAT) == 0)
    {
        return  open(path, options);
    }
    else
    {
        int      mode;
        va_list  args;
        va_start( args, options );
        mode = va_arg( args, int );
        va_end( args );
        return open(path, options, mode);
    }
}
#define  open    ___xxx_unix_open


/* normally provided by <cutils/misc.h> */
extern void*  load_file(const char*  pathname, unsigned*  psize);

/* normally provided by <cutils/sockets.h> */
extern int socket_loopback_client(int port, int type);
extern int socket_network_client(const char *host, int port, int type);
extern int socket_loopback_server(int port, int type);
extern int socket_inaddr_any_server(int port, int type);

/* normally provided by "fdevent.h" */

#define FDE_READ              0x0001
#define FDE_WRITE             0x0002
#define FDE_ERROR             0x0004
#define FDE_DONT_CLOSE        0x0080

typedef struct fdevent fdevent;

typedef void (*fd_func)(int fd, unsigned events, void *userdata);

fdevent *fdevent_create(int fd, fd_func func, void *arg);
void     fdevent_destroy(fdevent *fde);
void     fdevent_install(fdevent *fde, int fd, fd_func func, void *arg);
void     fdevent_remove(fdevent *item);
void     fdevent_set(fdevent *fde, unsigned events);
void     fdevent_add(fdevent *fde, unsigned events);
void     fdevent_del(fdevent *fde, unsigned events);
void     fdevent_loop();

struct fdevent {
    fdevent *next;
    fdevent *prev;

    int fd;
    int force_eof;

    unsigned short state;
    unsigned short events;

    fd_func func;
    void *arg;
};

static __inline__ void  sdb_sleep_ms( int  mseconds )
{
    Sleep( mseconds );
}

extern int  sdb_socket_accept(int  serverfd, struct sockaddr*  addr, socklen_t  *addrlen);

#undef   accept
#define  accept  ___xxx_accept

static __inline__  int  sdb_socket_setbufsize( int   fd, int  bufsize )
{
    int opt = bufsize;
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&opt, sizeof(opt));
}

extern int  sdb_socketpair( int  sv[2] );

static __inline__  char*  sdb_dirstart( const char*  path )
{
    char*  p  = strchr(path, '/');
    char*  p2 = strchr(path, '\\');

    if ( !p )
        p = p2;
    else if ( p2 && p2 > p )
        p = p2;

    return p;
}

static __inline__  char*  sdb_dirstop( const char*  path )
{
    char*  p  = strrchr(path, '/');
    char*  p2 = strrchr(path, '\\');

    if ( !p )
        p = p2;
    else if ( p2 && p2 > p )
        p = p2;

    return p;
}

static __inline__  int  sdb_is_absolute_host_path( const char*  path )
{
    return isalpha(path[0]) && path[1] == ':' && path[2] == '\\';
}

#else /* !_WIN32 a.k.a. Unix */

#include "fdevent.h"
#include "sockets.h"
#include "properties.h"
// tizen specific #include <cutils/misc.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>

#define OS_PATH_SEPARATOR '/'
#define OS_PATH_SEPARATOR_STR "/"

typedef  pthread_mutex_t          sdb_mutex_t;

#define  SDB_MUTEX_INITIALIZER    PTHREAD_MUTEX_INITIALIZER
#define  sdb_mutex_init           pthread_mutex_init
#define  sdb_mutex_lock           pthread_mutex_lock
#define  sdb_mutex_unlock         pthread_mutex_unlock
#define  sdb_mutex_destroy        pthread_mutex_destroy

#define  SDB_MUTEX_DEFINE(m)      sdb_mutex_t   m = PTHREAD_MUTEX_INITIALIZER

#define  sdb_cond_t               pthread_cond_t
#define  sdb_cond_init            pthread_cond_init
#define  sdb_cond_wait            pthread_cond_wait
#define  sdb_cond_broadcast       pthread_cond_broadcast
#define  sdb_cond_signal          pthread_cond_signal
#define  sdb_cond_destroy         pthread_cond_destroy

/* declare all mutexes */
#define  SDB_MUTEX(x)   extern sdb_mutex_t  x;
#include "mutex_list.h"

static __inline__ int  close_on_exec(int  fd)
{
    return fcntl( fd, F_SETFD, FD_CLOEXEC );
}

static __inline__ int  unix_open(const char*  path, int options,...)
{
    if ((options & O_CREAT) == 0)
    {
        return  open(path, options);
    }
    else
    {
        int      mode;
        va_list  args;
        va_start( args, options );
        mode = va_arg( args, int );
        va_end( args );
        return open(path, options, mode);
    }
}

static __inline__ int  sdb_open_mode( const char*  pathname, int  options, int  mode )
{
    return open( pathname, options, mode );
}


static __inline__ int  sdb_open( const char*  pathname, int  options )
{
    int  fd = open( pathname, options );
    if (fd < 0)
        return -1;
    close_on_exec( fd );
    return fd;
}
#undef   open
#define  open    ___xxx_open

static __inline__ int  sdb_shutdown(int fd)
{
    return shutdown(fd, SHUT_RDWR);
}
#undef   shutdown
#define  shutdown   ____xxx_shutdown

static __inline__ int  sdb_close(int fd)
{
    return close(fd);
}
#undef   close
#define  close   ____xxx_close


static __inline__  int  sdb_read(int  fd, void*  buf, size_t  len)
{
    return read(fd, buf, len);
}

#undef   read
#define  read  ___xxx_read

static __inline__  int  sdb_write(int  fd, const void*  buf, size_t  len)
{
    return write(fd, buf, len);
}
#undef   write
#define  write  ___xxx_write

static __inline__ int   sdb_lseek(int  fd, int  pos, int  where)
{
    return lseek(fd, pos, where);
}
#undef   lseek
#define  lseek   ___xxx_lseek

static __inline__  int    sdb_unlink(const char*  path)
{
    return  unlink(path);
}
#undef  unlink
#define unlink  ___xxx_unlink

static __inline__  int  sdb_creat(const char*  path, int  mode)
{
    int  fd = creat(path, mode);

    if ( fd < 0 )
        return -1;

    close_on_exec(fd);
    return fd;
}
#undef   creat
#define  creat  ___xxx_creat

static __inline__ int  sdb_socket_accept(int  serverfd, struct sockaddr*  addr, socklen_t  *addrlen)
{
    int fd;

    fd = accept(serverfd, addr, addrlen);
    if (fd >= 0)
        close_on_exec(fd);

    return fd;
}

#undef   accept
#define  accept  ___xxx_accept

#define  unix_read   sdb_read
#define  unix_write  sdb_write
#define  unix_close  sdb_close

typedef  pthread_t                 sdb_thread_t;

typedef void*  (*sdb_thread_func_t)( void*  arg );

static __inline__ int  sdb_thread_create( sdb_thread_t  *pthread, sdb_thread_func_t  start, void*  arg )
{
    pthread_attr_t   attr;

    pthread_attr_init (&attr);
    pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);

    return pthread_create( pthread, &attr, start, arg );
}

static __inline__  int  sdb_socket_setbufsize( int   fd, int  bufsize )
{
    int opt = bufsize;
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
}

static __inline__ void  disable_tcp_nagle(int fd)
{
    int  on = 1;
    setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, (void*)&on, sizeof(on) );
}


static __inline__ int  unix_socketpair( int  d, int  type, int  protocol, int sv[2] )
{
    return socketpair( d, type, protocol, sv );
}

static __inline__ int  sdb_socketpair( int  sv[2] )
{
    int  rc;

    rc = unix_socketpair( AF_UNIX, SOCK_STREAM, 0, sv );
    if (rc < 0)
        return -1;

    close_on_exec( sv[0] );
    close_on_exec( sv[1] );
    return 0;
}

#undef   socketpair
#define  socketpair   ___xxx_socketpair

static __inline__ void  sdb_sleep_ms( int  mseconds )
{
    usleep( mseconds*1000 );
}

static __inline__ int  sdb_mkdir(const char*  path, int mode)
{
    return mkdir(path, mode);
}
#undef   mkdir
#define  mkdir  ___xxx_mkdir

static __inline__ void  sdb_sysdeps_init(void)
{
}

static __inline__ char*  sdb_dirstart(const char*  path)
{
    return strchr(path, '/');
}

static __inline__ char*  sdb_dirstop(const char*  path)
{
    return strrchr(path, '/');
}

static __inline__  int  sdb_is_absolute_host_path( const char*  path )
{
    return path[0] == '/';
}

static __inline__  char* ansi_to_utf8(const char *str)
{
    // Not implement!
    // If need, use iconv later event though unix system is using utf8 encoding.
    int len;
    char *utf8;

    len = strlen(str);
    utf8 = (char *)calloc(len+1, sizeof(char));
    strcpy(utf8, str);
    return utf8;
}

#endif /* !_WIN32 */

#endif /* _SDB_SYSDEPS_H */
