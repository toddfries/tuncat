/*
 * Copyright (c) 2005 Kenjiro Cho
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if_tun.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <err.h>

#define MAX_PKTSIZE	(65536+8)	/* will packets ever be bigger? */

/* packet buffer structure */
struct pbuf {
	struct	pbuf *pb_next;
	u_int	pb_len;
	u_int	pb_seq;
	struct	timeval pb_time;
	u_char	pb_buf[MAX_PKTSIZE];
};

/* simple fifo queue structure */
struct queue {
	struct	pbuf *tail;	/* tail of packet queue */
	int	qlen;		/* queue length (in number of packets) */
	int	qlim;		/* queue limit (in number of packets) */
};

/* tunbridge statistics */
struct tb_stats {
	struct	timeval time;		/* timestamp */
	u_int64_t	rcvd_packets;	/* cumulative received packets */
	u_int64_t	rcvd_bytes;	/* cumulative received bytes */
	u_int64_t	sent_packets;	/* cumulative sent packets */
	u_int64_t	sent_bytes;	/* cumulative sent bytes */
	u_int64_t	shaped;		/* cumulative shaped packets */
	u_int64_t	dropped;	/* cumulative dropped packets */
	u_int64_t	discrepancy;	/* cumulative differences between
					 * supposed and actual sending times */
};

void usage(void);
void sig_handler(int);
int event_loop(int, int);
void print_stats(void);
void enqueue(struct queue *, struct pbuf *);
struct pbuf *dequeue(struct queue *);
void flushqueue(struct queue *);
void pbuf_dump(struct pbuf *);
struct	pbuf *read_packet(int);
int write_packet(int, struct pbuf *);
int is_pkt_ready(struct queue *, struct timeval *);

const	char *devicea = "/dev/tun0";
const	char *deviceb = "/dev/tun1";
long	bit_err = 0;
double	shaping = 0;
int	queue_limit = 500;
int	report_interval = 5000;		/* report every 5 seconds */

struct	queue *delay_queue;
struct	tb_stats stats, last_stats;
int	verbose;
int	done;
int	seq;

#define	TV_LE(a, b) (((a)->tv_sec < (b)->tv_sec) ||  \
	(((a)->tv_usec <= (b)->tv_usec) && ((a)->tv_sec == (b)->tv_sec)))

#define TV_DIFF_INMS(a, b)  (((a)->tv_sec - (b)->tv_sec) * 1000 + \
			    ((a)->tv_usec - (b)->tv_usec) / 1000)

#define	qhead(q)	((q)->tail ? (q)->tail->pb_next : NULL)
#define	qempty(q)	((q)->qlen == 0)

void usage(void)
{
	printf("usage: tunbridge [-qv]\n\n");
}

void
sig_handler(int sig)
{
	if (sig == SIGUSR1) {
		print_stats();
		return;
	}

	done = 1;
}

int
main(int argc, char **argv)
{
	int	ch, fda, fdb;

	while ((ch = getopt(argc, argv,
	    "l:n:o:qv")) != EOF) {
		switch (ch) {
		case 'l':
			queue_limit = (int)strtol(optarg, NULL, 0);
			break;
		case 'n':
			devicea = optarg;
			break;
		case 'o':
			deviceb = optarg;
			break;
		case 'q':
			verbose = -1;
			report_interval = 0;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	signal(SIGINT, sig_handler);
	signal(SIGHUP, sig_handler);
	signal(SIGUSR1, sig_handler);

	if ((fda = open(devicea, O_RDWR)) == -1)
		err(1, "can't open %s", devicea);
	if ((fdb = open(deviceb, O_RDWR)) == -1)
		err(1, "can't open %s", deviceb);

	if (verbose >= 0) {
		printf("tunbridge started for %s <-> %s\n", devicea, deviceb);
	}

	event_loop(fda, fdb);

	flushqueue(delay_queue);
	free(delay_queue);

	close(fda);
	close(fdb);

	return 0;
}

int
event_loop(int fda, int fdb)
{
	struct	pollfd pfd[2];
	struct	timeval cur_time;
	struct	pbuf *p;
	int	nfds, timeout;

	while (!done) {
		timeout = report_interval;

		pfd[0].fd = fda;
		pfd[0].events = POLLIN;
		pfd[1].fd = fdb;
		pfd[1].events = POLLIN;
		nfds = poll(pfd, 2, timeout);
		if (nfds == -1 && errno == EINTR)
			continue;
		if (nfds == -1  ||
		    (pfd[0].revents & (POLLERR|POLLHUP|POLLNVAL)) ||
		    (pfd[1].revents & (POLLERR|POLLHUP|POLLNVAL))
		)
			errx(1, "poll");

		gettimeofday(&cur_time, NULL);

		if (verbose > 0)
			fprintf(stderr, "poll: nfds=%d, timeout=%d\n",
			    nfds, timeout);

		/* read packets from device */
		if (nfds > 0) {
			if (pfd[0].revents & POLLIN) {
				if ((p = read_packet(fda)) != NULL) {
					p->pb_time = cur_time;

					write_packet(fdb, p);
				}
			}
			if (pfd[1].revents & POLLIN) {
				if ((p = read_packet(fdb)) != NULL) {
					p->pb_time = cur_time;

					write_packet(fda, p);
				}
			}
		}

		if (report_interval > 0 &&
		    TV_DIFF_INMS(&cur_time, &stats.time) > report_interval)
			print_stats();
	}
	return (0);
}

void
print_stats(void)
{
#if 0
	long	t;
	u_int64_t	diff_sent_packets, diff_sent_bytes;

	gettimeofday(&stats.time, NULL);

	diff_sent_packets = stats.sent_packets - last_stats.sent_packets;
	diff_sent_bytes = stats.sent_bytes - last_stats.sent_bytes;

	printf("\nqueue len:%d/%d\n", delay_queue->qlen, delay_queue->qlim);
	printf("recved:%llu pkts (%llu bytes) sent:%llu pkts (%llu bytes)\n",
	    stats.rcvd_packets - last_stats.rcvd_packets,
	    stats.rcvd_bytes - last_stats.rcvd_bytes,
	    diff_sent_packets, diff_sent_bytes);
	printf("shaped:%llu pkts dropped:%llu pkts\n",
	    stats.shaped - last_stats.shaped,
	    stats.dropped - last_stats.dropped);

	t = TV_DIFF_INMS(&stats.time, &last_stats.time);
	printf("avg throughput:%.2f kbps avg discrepancy:%.2f ms\n",
	    t ? (double)(stats.sent_bytes - last_stats.sent_bytes) / t * 8 : 0,
	    diff_sent_packets ?
	    (double)(stats.discrepancy - last_stats.discrepancy)
	    / diff_sent_packets : 0);

	last_stats = stats;
#endif
}

void
enqueue(struct queue *q, struct pbuf *p)
{
	if (q->tail != NULL) {
		p->pb_next = q->tail->pb_next;
		q->tail->pb_next = p;
	} else
		p->pb_next = p;
	q->tail = p;
	q->qlen++;
}

struct pbuf *
dequeue(struct queue *q)
{
	struct	pbuf *p, *p0;

	if ((p = q->tail) == NULL)
		return (NULL);
	if ((p0 = p->pb_next) != p)
		p->pb_next = p0->pb_next;
	else
		q->tail = NULL;
	q->qlen--;
	p0->pb_next = NULL;
	return (p0);
}

void
flushqueue(struct queue *q)
{
	struct	pbuf *p;

	while ((p = dequeue(q)) != NULL)
		free(p);
}

void
pbuf_dump(struct pbuf *p)
{
	int	i;

	for (i=0; i<p->pb_len; i++) {
		if (i % 2 == 0)
			fprintf(stderr, " ");
		fprintf(stderr, "%02x", (u_int)p->pb_buf[i]);
		if (i % 20 == 19)
			fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n");
}

struct	pbuf *
read_packet(int fd)
{
	struct	pbuf *p;
	ssize_t	n;

	if ((p = malloc(sizeof(*p))) == NULL)
		return (NULL);
	n = read(fd, p->pb_buf, sizeof(p->pb_buf));
	if (n <= 0) {
		free(p);
		return (NULL);
	}
	p->pb_next = NULL;
	p->pb_len = (u_int)n;
	p->pb_seq = ++seq;

	stats.rcvd_packets++;
	stats.rcvd_bytes += n;

	if (verbose > 0) {
		fprintf(stderr, "%2d: read_packet: %u bytes seq=%u\n",
		    fd, p->pb_len, p->pb_seq);
		if (verbose > 1)
			pbuf_dump(p);
	}

	return (p);
}

int
write_packet(int fd, struct pbuf *p)
{
	ssize_t	n;

	n = write(fd, p->pb_buf, p->pb_len);
	if (n != p->pb_len)
		warnx("write_packet: wrote only %u/%u bytes", n, p->pb_len);
	if (verbose > 0)
		fprintf(stderr, "%2d: write_packet: wrote %u bytes seq=%u\n",
			    fd, n, p->pb_seq);
	free(p);
	stats.sent_packets++;
	stats.sent_bytes += n;
	return ((int)n);
}

int
is_pkt_ready(struct queue *q, struct timeval *cur)
{
	struct	pbuf *p;

	if ((p = qhead(q)) == NULL)
		return (0);
	if (TV_LE(&p->pb_time, cur))
		return (1);
	return (0);
}

