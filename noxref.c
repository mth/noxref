/*
 * Copyright (c) 2013 Madis Janson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <poll.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>

#define CLIENT	0
#define SERVER	1
#define BUF_SIZE		0x5800
#define MAX_HEADERS_SIZE	0x5400

#define ERR_IO		-1
#define ERR_WRITE       -2
#define ERR_CONNECT	-3
#define ERR_RESOLV	-4
#define ERR_BAD_REQ	-5
#define ERR_NO_HOST	-6
#define ERR_REFUSED	-7
#define ERR_EMPTY_GIF	-8
#define ERR_READ_REQ	-9

static const char const empty_gif[] =
	"HTTP/1.0 200 OK\r\n"
	"Content-Length: 43\r\n"
	"Content-Type: image/gif\r\n"
	"Cache-Control: max-age=600000\r\n"
	"\r\n"
	"GIF89a\1\0\1\0\x80\0\0\xff\xff\xff\xff\xff\xff"
	"!\xf9\4\1\12\0\1\0,\0\0\0\0\1\0\1\0\0\2\2L\1\0;";

typedef struct hostname {
	struct hostname *next;
	int len;
	char name[1];
} *hostname;

static hostname whitelist;
static struct in_addr listen_addr;
static int listen_port = 880;
static int use_uid = 65534;
static int use_gid = 65534;
static struct timeval recv_timeout = { 1, 0 };
static struct timeval send_timeout = { 7, 0 };
static int inactivity_timeout = 300;

static int full_write(int fd, const char *buf, int size) {
	int n;

	for (; size > 0; size -= n, buf += n)
		if ((n = send(fd, buf, size, MSG_NOSIGNAL)) <= 0)
			return n;
	return 1;
}

static int wstr(int fd, const char *str) {
	return full_write(fd, str, strlen(str));
}

static unsigned read_http_header(int fd, char *buf) {
	int n, from, size = 0;
	char *end = NULL;

	*buf = 0;
	while ((n = MAX_HEADERS_SIZE - size) >= 16 &&
	       !end && (n = read(fd, buf + size, n)) > 0) {
		from = size - 3;
		if (from < 0)
			from = 0;
		buf[size += n] = 0;
		end = strstr(buf + from, "\r\n\r\n");
	}
	from = end ? end - buf : size;
	return n < 0 || size <= 0 ? -1U : size | (unsigned) from << 16;
}

static int subdomain(char *host, int host_len, char *domain, int domain_len) {
	int from;

	from = host_len - domain_len;
	return (!from || from > 0 && host[from - 1] == '.') &&
	       !memcmp(host + from, domain, domain_len);
}

static int no_referer_match(char *host, char *referer) {
	int host_len, referer_len, skip;
	hostname h;

	skip = strcspn(referer, ".:/\r\n");
	if (referer[skip] == '.')
		++skip;
	referer_len = strcspn(referer += skip, ":/\r\n");
	if (!memchr(referer, '.', referer_len)) {
		referer_len += skip;
		referer -= skip;
	}
	host_len = strcspn(host, ":");
	if (subdomain(host, host_len, referer, referer_len))
		return 0; // ok
	for (h = whitelist; h; h = h->next)
		if (subdomain(host, host_len, h->name, h->len))
			return 0;
	return -1; // no match, shouldn't be allowed
}

static void init_sock(int fd) {
	static const int opt = 1;

	setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &opt, sizeof opt);
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
		   &recv_timeout, sizeof recv_timeout);
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
		   &send_timeout, sizeof send_timeout);
}

static int connect_host(char *host) {
	struct addrinfo hint, *addr;
	char *port;
	int fd;

	if ((port = strchr(host, ':')))
		*port = 0;
	memset(&hint, 0, sizeof hint);
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_flags = AI_ADDRCONFIG;
	if (getaddrinfo(host, port ? port + 1 : "http", &hint, &addr))
		return ERR_RESOLV;
	if (port)
		*port = ':';
	fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	init_sock(fd);
	if (fd < 0)
		goto free;
	if (connect(fd, addr->ai_addr, addr->ai_addrlen)) {
		close(fd);
		fd = ERR_CONNECT;
	}
free:
	freeaddrinfo(addr);
	return fd;
}

static inline int invalid(char *buf, char *ptr, unsigned size) {
	return !ptr || ptr < buf || ptr + size > buf + BUF_SIZE;
}

static int prepare_http(int fd, char *buf) {
	int host_fd, hdr_size, len_diff;
	unsigned size, path_len, host_len, move_len;
	char *h, *p, *host = NULL, *referer = NULL, *referer_end, *path;

	if ((size = read_http_header(fd, buf)) == -1U)
		return ERR_READ_REQ;
	hdr_size = size >> 16;
	size &= 0xffff;
	if (invalid(buf, buf, hdr_size + 4))
		return ERR_BAD_REQ;
	// buf has enough space after size even when "\r\n\r\n" was not found,
	// because MAX_HEADERS_SIZE - BUF_SIZE > 2
	buf[hdr_size + 2] = 0; // "\r\n\r\n" -> "\r\n\0\n"
	if (!(path = strpbrk(buf, " \r\n")))
		return ERR_BAD_REQ;
	path_len = strcspn(++path, " \r\n");
	p = strstr(path + path_len, "\r\n");
	while (p && (!host || !referer) && (p = strstr(h = p + 2, "\r\n")))
		if (!strncasecmp(h, "host:", 5)) {
			host = h + 5;
			host += strspn(host, " \t");
			host_len = p - host;
		} else if (!strncasecmp(h, "referer:", 8)) {
			referer = h + 8;
			referer += strspn(referer, " \t");
			referer += strcspn(referer, "/\r\n");
			referer += strspn(referer, "/");
			referer_end = p;
		}
	if (invalid(buf, host, host_len + 1))
		return ERR_NO_HOST;
	host[host_len] = 0;
	if (referer && no_referer_match(host, referer)) {
		if (path_len > 3 && !memcmp(path + path_len - 3, ".js", 3)) {
			syslog(LOG_DEBUG | LOG_DAEMON, "refused: %s", host);
			return ERR_REFUSED; // javascript cross-reference
		}
		if (path_len > 4 && !memcmp(path + path_len - 4, ".gif", 4)
		    && strchr(path, '?')) {
			syslog(LOG_DEBUG | LOG_DAEMON, "refused gif: %s", host);
			return ERR_EMPTY_GIF;
		}
	} else {
		referer = NULL; // matches, don't remove
	}
	host_fd = connect_host(host);
	if (host_fd < 0)
		return host_fd;
	host[host_len] = '\r';
	buf[hdr_size + 2] = '\r';
	len_diff = BUF_SIZE;
	if (referer)
		len_diff = host_len + 1 - (referer_end - referer);
	if (len_diff < BUF_SIZE - MAX_HEADERS_SIZE) {
		p = host_len + 1 + referer;
		move_len = buf + size - referer_end;
		if (invalid(buf, p, move_len) ||
		    invalid(buf, referer_end, move_len) ||
		    invalid(buf, referer, host_len))
			return ERR_BAD_REQ;
		memmove(p, referer_end, move_len);
		size += len_diff;
		if (host > referer)
			host += len_diff;
		memcpy(referer, host, host_len);
		referer[host_len] = '/';
	}
	if (full_write(host_fd, buf, size) <= 0) {
		close(host_fd);
		return ERR_WRITE;
	}
	return host_fd;
}

static void write_error(char *buf, int fd, int error) {
	const char *message, *status = "502 Bad Gateway";
	switch (error) {
	case ERR_IO:
		message = "Error reading from remote host";
		break;
	case ERR_WRITE:
		message = "Error writing to remote host";
		break;
	case ERR_CONNECT:
		message = "Error connecting to host";
		break;
	case ERR_RESOLV:
		message = "Error on resolving the hostname";
		break;
	case ERR_BAD_REQ:
		status = "400 Bad Request";
		message = "Malformed request";
		break;
	case ERR_NO_HOST:
		status = "400 No Host";
		message = "Hostname not given in the request";
		break;
	case ERR_REFUSED:
		status = "200 Ok";
		message = "";
		break;
	case ERR_EMPTY_GIF:
		full_write(fd, empty_gif, sizeof empty_gif);
	case ERR_READ_REQ:
		return;
	default:
		message = "Unknown error";
	}
	snprintf(buf, BUF_SIZE, "HTTP/1.1 %s\r\nConnection: close\r\n"
	         "Content-length: %d\r\n"
		 "Content-type: text/plain\r\n\r\n%s\n",
		 status, strlen(message) + 1, message);
	buf[BUF_SIZE - 1] = 0;
	full_write(fd, buf, strlen(buf));
}

static int send_data(char *buf, int type, struct pollfd *in, int out_fd) {
	int i, n;
	n = read(in->fd, buf, BUF_SIZE);
	if (!n && type == CLIENT) {
		in->events = POLLHUP | POLLERR;
		return shutdown(out_fd, SHUT_WR) ? ERR_WRITE : 1;
	}
	if (n <= 0)
		return ERR_IO;
	if (full_write(out_fd, buf, n) <= 0)
		return ERR_WRITE;
	return 1;
}

static void* process_connection(void *arg) {
	struct pollfd fds[2];
	char buf[BUF_SIZE];
	int i = CLIENT, res;

	init_sock(fds[CLIENT].fd = (long) arg);
	fds[CLIENT].events = POLLIN | POLLERR | POLLHUP;
	fds[SERVER].fd = -1;
	fds[SERVER].events = POLLIN | POLLERR | POLLHUP;
	fds[SERVER].fd = res = prepare_http(fds[CLIENT].fd, buf);
	while (res >= 0) {
		i = SERVER;
		if (!(res = poll(fds, 2, inactivity_timeout * 1000)))
			break;
		for (i = 0; res > 0 && i < 2; ++i)
			if ((fds[i].revents & POLL_IN))
				res = send_data(buf, i, fds + i, fds[i ^ 1].fd);
			else if ((fds[i].revents & (POLLERR | POLLHUP)))
				res = ERR_IO;
	}
	if (res < 0 && (i == SERVER || res != ERR_IO))
		write_error(buf, fds[CLIENT].fd, res);
	if (fds[SERVER].fd >= 0)
		close(fds[SERVER].fd);
	close(fds[CLIENT].fd);
	return NULL;
}

static int listen_socket() {
	int sock = -1, value = 1;
	struct sockaddr_in sa;
	const char *err;

	err = "socket: %s";
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)
		goto hell;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof value);
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_addr = listen_addr;
	sa.sin_port = htons(listen_port);
	err = "bind: %s";
	if (bind(sock, (struct sockaddr*) &sa, sizeof sa))
		goto hell;
	err = "listen: %s";
	if (!listen(sock, 64))
		return sock;
hell:
	syslog(LOG_ERR | LOG_DAEMON, err, strerror(errno));
	if (sock != -1)
		close(sock);
	return -1;
}

static int accept_connections(int listen_fd) {
	pthread_attr_t pta;
	pthread_t th;
	long fd;

	pthread_attr_init(&pta);
	pthread_attr_setdetachstate(&pta, PTHREAD_CREATE_DETACHED);
	while ((fd = accept(listen_fd, NULL, NULL)) >= 0)
		if (pthread_create(&th, &pta, process_connection, (void*) fd))
			close(fd);
	syslog(LOG_ERR | LOG_DAEMON, "accept: %s", strerror(errno));
	return 1;
}

static void read_conf() {
	const char *conf = "/etc/noxref.conf";
	int len, sect = 0;
	FILE *f;
	char *line, buf[1024];

	if (!(f = fopen(conf, "r"))) {
		syslog(LOG_ERR | LOG_DAEMON, "%s: %s", conf, strerror(errno));
		return;
	}
	while (fgets(buf, sizeof buf, f)) {
		for (line = buf; *line == ' ' || *line == '\t'; ++line);
		for (len = strlen(line); --len > 0 && line[len] == '\n';);
		if (!++len || *line == '#')
			continue;
		line[len] = 0;
		if (!strcmp(line, "allow:")) {
			sect = 1;
		} else if (sect == 1) {
			hostname h = malloc(sizeof *h + len);
			memcpy(h->name, line, len + 1);
			h->len = len;
			h->next = whitelist;
			whitelist = h;
		} else if (!strncmp(line, "listen:", 7)) {
			line += 7;
			line += strspn(line, " \t");
			if (!inet_aton(line, &listen_addr))
				syslog(LOG_ERR | LOG_DAEMON,
				       "invalid listen address (%s)", line);
		} else {
			sscanf(line, "port: %d", &listen_port);
			sscanf(line, "uid: %d", &use_uid);
			sscanf(line, "gid: %d", &use_gid);
			sscanf(line, "inactivity-timeout: %d",
			       &inactivity_timeout);
			sscanf(line, "read-timeout: %ld", &recv_timeout.tv_sec);
			sscanf(line, "send-timeout: %ld", &send_timeout.tv_sec);
		}
	}
	fclose(f);
}

int main(int argc, char **argv) {
	int listen_fd;

	read_conf();
	if ((listen_fd = listen_socket()) < 0)
		return 1;
	setgid(use_gid);
	setuid(use_uid);
	return accept_connections(listen_fd);
}
