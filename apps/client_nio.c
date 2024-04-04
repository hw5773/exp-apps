#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <openssl/opensslv.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <getopt.h>
#include <debug.h>

#define TIMEOUT 3000
#define MAX_DOMAIN_LENGTH 255
#define FAIL    -1
#define EXT_LENGTH 4
#define PORT 443

int dtype = EXP_DEBUG_ALL;
int open_connection(const char *hostname, int port);
int get_next(FILE *fp, int *rank, char *hostname);
void make_log_file(int rank, char *hostname);
void clear_log_file(int err);
int is_progress();
int is_accessible(int fd, size_t msec, int flag);
int is_readable(int fd, size_t msec);
int is_writeable(int fd, size_t msec);
SSL_CTX* init_client_ctx(void);
FILE *fp, *err, *ips;
int complete, result;
char ip[16];

enum {
  SOCK_FLAG = 1,
  SOCK_READABLE = SOCK_FLAG,
  SOCK_WRITEABLE = SOCK_FLAG << 1
};

int usage(const char *pname)
{
  fstart();
  emsg(">> Usage: %s [options]", pname);
  emsg(">> Options");
  emsg("  -n, --hostname  Hostname of a server");
  emsg("  -p, --port      Port number of a server");
  ffinish();
  exit(1);
}

unsigned long get_current_clock_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main(int argc, char *argv[])
{
	int i, c, fd, maxfd, port, ret, trial;
  size_t timeout;
  char *hostname, *pname;
  SSL *ssl;
  SSL_CTX *ctx;
  struct timeval tv, ts;
  fd_set fds, readfds;
  double stime;

  hostname = NULL;
  pname = argv[0];

  maxfd = -1;
  port = -1;
  timeout = 10;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"hostname", required_argument, 0, 'n'},
      {"port", required_argument, 0, 'p'},
      {0, 0, 0, 0}
    };

    const char *opt = "n:p:0";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

    if (c == -1)
      break;

    switch (c)
    {
      case 'n':
        hostname = optarg;
        break;

      case 'p':
        port = atoi(optarg);
        break;

      default:
        usage(pname);
    }
  }

  if (!hostname)
  {
    emsg("The hostname is not set.");
    emsg("Please try again.");
    usage(pname);
  }

  if (port < 0)
  {
    emsg("The port number is not set or incorectly set.");
    emsg("Please try again.");
    usage(pname);
  }

  srand(time(NULL));
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  fd = open_connection(hostname, port);
  if (fd > maxfd)
  {
    maxfd = fd;
  }
  else if (fd == -500)
  {
    fprintf(stderr, "dns failure\n");
  }
  else if (fd < 0)
  {
    fprintf(stderr, "socket failure\n");
  }

  complete = 0;
  result = 0;
  ctx = init_client_ctx();
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, hostname);

  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  tv.tv_sec = TIMEOUT/1000;
  tv.tv_usec = 0;

  if (select(maxfd + 1, NULL, &fds, NULL, &tv) == 1)
  {
    int so_error;
    socklen_t len = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);

    if (!so_error)
    {
      while (1)
      {
        ret = SSL_connect(ssl);

        if (ret < 0)
        {
          switch (SSL_get_error(ssl, ret))
          {
            case SSL_ERROR_WANT_READ:
              if (is_readable(fd, timeout))
              {
                printf("ssl_error_want_read readable\n");
                continue;
              }
              printf("ssl_error_want_read not readable\n");
              break;
            case SSL_ERROR_WANT_WRITE:
              if (is_writeable(fd, timeout))
              {
                printf("ssl_error_want_read writable\n");
                continue;
              }
              printf("ssl_error_want_read not writable\n");
              break;
            case SSL_ERROR_SYSCALL:
              if (is_progress())
              {
                printf("ssl_error_syscall in progress\n");
                if (SSL_want_write(ssl))
                {
                  if (is_writeable(fd, timeout))
                    continue;
                }
                else if (SSL_want_read(ssl))
                {
                  if (is_readable(fd, timeout))
                    continue;
                }
              }
              else
              {
                printf("ssl_error_syscall not in progress\n");
                break;
              }
          }
        }
        else if (ret == 0)
        {
          printf("The return value of SSL_connect() is 0\n");
          break;
        }
        else
        {
          printf("The return value of SSL_connect() is 1\n");
          break;
        }
      }
      SSL_free(ssl);
    }
    else
    {
      printf("so error!\n");
      fprintf(stderr, "timeout");
      close(fd);
      fprintf(stderr, " (socket closed) ");
    }

    if (result)
    {
      close(fd);
      fprintf(stderr, " (socket closed) \n");
    } 
    else
    {
      close(fd);
      fprintf(stderr, " (socket closed) none\n");
    }
  }
    printf("nio 18\n");
  SSL_CTX_free(ctx);

  return 0;
}

void sighandler(int signum)
{
  signal(SIGALRM, SIG_IGN);
  fprintf(stderr, "sig alarm ");
  signal(SIGALRM, sighandler);
}

int open_connection(const char *hostname, int port)
{   
    int sd, ret, err, optval = 0;
    socklen_t optlen = sizeof(optval);
    char addrstr[100];
    void *ptr;
    struct addrinfo *res;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;
 
    signal(SIGALRM, sighandler);

    alarm(5);
    err = getaddrinfo(hostname, "443", &hints, &res);
    signal(SIGALRM, SIG_DFL);
    alarm(0);

    if (err != 0)
      return -500;

    inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);
    ptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
    inet_ntop(res->ai_family, ptr, addrstr, 100);

    fprintf(stderr, "%s ", addrstr);

    if ((sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) goto err;
    fcntl(sd, F_SETFL, O_NONBLOCK);

    if (setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) goto err;

    connect(sd, res->ai_addr, res->ai_addrlen);

    return sd;
err:
    close(sd);
    fprintf(stderr, " (socket closed in error) ");
    return -1;
}

void msg_callback(int write, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
    int i, ht;
    unsigned char *p;
    p = (unsigned char *)buf;

    printf("msg_callback 1\n");
    if (content_type == 256)
    {
    printf("msg_callback 2\n");
      fprintf(fp, "Record Header: %lu\n", len);
    printf("msg_callback 3\n");
      fwrite(p, 1, len, fp);
    printf("msg_callback 4\n");
      fprintf(fp, "\n");
    printf("msg_callback 5\n");
    }
    else
    {
    printf("msg_callback 6\n");
      ht = *p;
    printf("msg_callback 7\n");
      if (ht == content_type) return;
    printf("msg_callback 8\n");
      (ht - 1)? fprintf(fp, "Server Hello: %lu\n", len) : fprintf(fp, "Client Hello: %lu\n", len);
    printf("msg_callback 9\n");
      fwrite(p, 1, len, fp);
    printf("msg_callback 10\n");
      fprintf(fp, "\n");
    printf("msg_callback 11\n");
    }

    printf("msg_callback 12\n");
    if (content_type == 22 && ht == 2)
    {
    printf("msg_callback 13\n");
      close(SSL_get_fd(ssl));
    printf("msg_callback 14\n");
      complete = 1;
    printf("msg_callback 15\n");
    }
    printf("msg_callback 16\n");
}

SSL_CTX* init_client_ctx(void)
{   
  SSL_METHOD *method;
  SSL_CTX *ctx;
        
  method = (SSL_METHOD *)TLS_client_method(); 
  ctx = SSL_CTX_new(method);
  if ( ctx == NULL )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }

	//SSL_CTX_set_msg_callback(ctx, msg_callback);

  return ctx;
}

int is_progress()
{
  return (errno == EAGAIN || errno == EINTR || errno == EINPROGRESS);
}

int is_accessible(int fd, size_t msec, int flag)
{
  fd_set rset, wset;
  struct timeval tv;

  FD_ZERO(&rset);
  FD_ZERO(&wset);

  fd_set *prset = NULL;
  fd_set *pwset = NULL;

  if (SOCK_READABLE & flag)
  {
    FD_SET(fd, &rset);
    prset = &rset;
  }

  if (SOCK_WRITEABLE & flag)
  {
    FD_SET(fd, &wset);
    pwset = &wset;
  }

  tv.tv_sec = msec/1000;
  tv.tv_usec = (msec % 1000) * 1000;

  if (select(fd + 1, prset, pwset, NULL, &tv) <= 0)
    return 0;
  return 1;
}

int is_readable(int fd, size_t msec)
{
  return is_accessible(fd, msec, SOCK_READABLE);
}

int is_writeable(int fd, size_t msec)
{
  return is_accessible(fd, msec, SOCK_WRITEABLE);
}
