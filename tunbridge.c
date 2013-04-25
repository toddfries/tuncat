/*	$Id$ */
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

#define MAX_PKTSIZE	2048	/* big enough for 1500 byte MTU */

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
int event_loop(int);
void print_stats(void);
void enqueue(struct queue *, struct pbuf *);
struct pbuf *dequeue(struct queue *);
void flushqueue(struct queue *);
void pbuf_dump(struct pbuf *);
struct	pbuf *read_packet(int);
int write_packet(int, struct pbuf *);
int is_pkt_ready(struct queue *, struct timeval *);
int emulate_loss(int);

const	char *device = "/dev/tun0";
int	delay_ms = 200;
long	loss_prob = 0;
long	bit_err = 0;
double	shaping = 0;
int	queue_limit = 500;
int	report_interval = 5000;		/* report every 5 seconds */

struct	queue *delay_queue;
struct	timeval delay_time, shape_time;
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
	printf("usage: tunbridge [-qv]\n"
	       "       [-b bit_error][-d delay_ms][-l queue_limit]\n"
	       "       [-n device][-p loss_prob][-s shaping[Kb|Mb|Gb]]\n");
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
	int	ch, fd;
	char	*cp;
	double	val;

	while ((ch = getopt(argc, argv,
	    "b:d:l:n:p:qs:v")) != EOF) {
		switch (ch) {
		case 'b':
			/* sanity check */
			val = strtod(optarg, NULL);
			if (val * 1500 * 8 >= 0x7fffffff)
				fprintf(stderr,
				    "bit errror rate %f too high\n", val);
			else {
				bit_err = (long)(strtod(optarg, NULL)
				    * 0x7fffffff);
				loss_prob = bit_err;
			}
			break;
		case 'd':
			delay_ms = (int)strtol(optarg, NULL, 0);
			break;
		case 'l':
			queue_limit = (int)strtol(optarg, NULL, 0);
			break;
		case 'n':
			device = optarg;
			break;
		case 'p':
			loss_prob = (long)(strtod(optarg, NULL) * 0x7fffffff);
			break;
		case 's':
			shaping = strtod(optarg, &cp);
			if (cp != NULL) {
				if (!strcmp(cp, "b"))
					; /* nothing */
				else if (!strcmp(cp, "Kb"))
					shaping *= 1000;
				else if (!strcmp(cp, "Mb"))
					shaping *= 1000 * 1000;
				else if (!strcmp(cp, "Gb"))
					shaping *= 1000 * 1000 * 1000;
			}
			shaping /= 8;	/* convert to bytes per sec */
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

	gettimeofday(&delay_time, NULL);
	srandom((u_int)delay_time.tv_usec);

	delay_time.tv_sec  = delay_ms / 1000;
	delay_time.tv_usec = (delay_ms % 1000) * 1000;

	if ((fd = open(device, O_RDWR)) == -1)
		err(1, "can't open %s", device);

	if ((delay_queue = malloc(sizeof(*delay_queue))) == NULL)
		err(1, "malloc");
	delay_queue->tail = NULL;
	delay_queue->qlen = 0;
	delay_queue->qlim = queue_limit;

	if (verbose >= 0) {
		printf("tunbridge started for %s\n", device);
		printf("  delay:%d ms  queue limit: %d pkts\n",
		    delay_ms, queue_limit);
		if (loss_prob != 0) {
			if (bit_err)
				printf("  bit error: %.3f\n",
				    (double)bit_err / 0x7fffffff);
			else
				printf("  packet loss: %.3f\n",
				    (double)loss_prob / 0x7fffffff);
		}
		if (shaping != 0)
			printf("  shaping: %.2f kbps\n", shaping * 8 / 1000);
	}

	event_loop(fd);

	flushqueue(delay_queue);
	free(delay_queue);

	close(fd);

	return 0;
}

int
event_loop(int fd)
{
	struct	pollfd pfd[1];
	struct	timeval cur_time;
	struct	pbuf *p;
	long	diff;
	int	nfds, timeout;

	while (!done) {
		/* compute the next timeout for poll(2) */
		if (qempty(delay_queue)) {
			if (report_interval > 0)
				timeout = report_interval;
			else
				timeout = -1;
		} else {
			gettimeofday(&cur_time, NULL);
			p = qhead(delay_queue);
			timeout = TV_DIFF_INMS(&p->pb_time, &cur_time);
			if (timeout < 0)
				timeout = 0;
		}

		pfd[0].fd = fd;
		pfd[0].events = POLLIN;
		nfds = poll(pfd, 1, timeout);
		if (nfds == -1 && errno == EINTR)
			continue;
		if (nfds == -1  ||
		    (pfd[0].revents & (POLLERR|POLLHUP|POLLNVAL)))
			errx(1, "poll");

		gettimeofday(&cur_time, NULL);

		/*
		 * if we have packets to reinject from the delay queue,
		 * write them to the tun device.
		 */
		while (is_pkt_ready(delay_queue, &cur_time)) {
			p = dequeue(delay_queue);
			if (p == NULL)
				errx(1, "dequeue");
			diff = TV_DIFF_INMS(&cur_time, &p->pb_time);
			if (verbose > 0)
				fprintf(stderr,
				    "packet ready: %ld ms behind\n", diff);
			stats.discrepancy += diff;
			write_packet(fd, p);
		}

		if (verbose > 0)
			fprintf(stderr, "poll: nfds=%d, timeout=%d\n",
			    nfds, timeout);

		/* read packets from device */
		if (nfds > 0 && (p = read_packet(fd)) != NULL) {

			/*
			 * compute the departing time of the packet
			 */
			/* first, check if shaping is in effect */
			if (shaping == 0 || TV_LE(&shape_time, &cur_time))
				shape_time = cur_time;
			else
				stats.shaped++;

			p->pb_time = shape_time;

			/* then, add the delay */
			p->pb_time.tv_sec += delay_time.tv_sec;
			p->pb_time.tv_usec += delay_time.tv_usec;
			if (p->pb_time.tv_usec > 1000000) {
				p->pb_time.tv_usec -= 1000000;
				p->pb_time.tv_sec++;
			}

			/* if shaping is set, update the shape time. */
			if (shaping != 0) {
				double delta;

				/*
				 * compute the time required to send this
				 * packet in seconds, and add it to the
				 * supposed finish time.  we need to subtract
				 * 4 bytes for the address family prepended
				 * for the tun device.
				 */
				delta = (double)(p->pb_len - 4) / shaping;
				shape_time.tv_sec += (long)delta;
				delta -= (long)delta;
				shape_time.tv_usec += delta * 1000000;
				if (shape_time.tv_usec > 1000000) {
					shape_time.tv_usec -= 1000000;
					shape_time.tv_sec++;
				}
			}

			/* emulate packet loss */
			if ((loss_prob != 0 && emulate_loss(p->pb_len) == 1) ||
			    delay_queue->qlen >= delay_queue->qlim) {
				free(p);
				stats.dropped++;
			} else {
				/* enqueue the packet to the delay queue */
				enqueue(delay_queue, p);
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
		fprintf(stderr, "read_packet: %u bytes seq=%u\n",
		    p->pb_len, p->pb_seq);
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
		fprintf(stderr, "write_packet: wrote %u bytes seq=%u\n",
			    n, p->pb_seq);
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

int
emulate_loss(int len)
{
	if (bit_err > 0) {
		if (random() < bit_err * len * 8)
			return (1);
		return (0);
	}

	if (random() < loss_prob)
		return (1);
	return (0);
}
