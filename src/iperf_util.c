/*
 * iperf, Copyright (c) 2014, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
/* iperf_util.c
 *
 * Iperf utility functions
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <errno.h>

#include "config.h"
#include "cjson.h"
#include "net.h"

#define NUM_NET_STATS 5
char *net_stats_label[] = {"duration", "rx_bytes", "rx_packets", "tx_bytes", "tx_packets"}; // duration must be first

#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <arpa/inet.h>
#include <math.h>

extern void mapped_v4_to_regular_v4(char *str);

/* make_cookie
 *
 * Generate and return a cookie string
 *
 * Iperf uses this function to create test "cookies" which
 * server as unique test identifiers. These cookies are also
 * used for the authentication of stream connections.
 */

void
make_cookie(char *cookie)
{
    static int randomized = 0;
    char hostname[500];
    struct timeval tv;
    char temp[1000];

    if ( ! randomized )
        srandom((int) time(0) ^ getpid());

    /* Generate a string based on hostname, time, randomness, and filler. */
    (void) gethostname(hostname, sizeof(hostname));
    (void) gettimeofday(&tv, 0);
    (void) snprintf(temp, sizeof(temp), "%s.%ld.%06ld.%08lx%08lx.%s", hostname, (unsigned long int) tv.tv_sec, (unsigned long int) tv.tv_usec, (unsigned long int) random(), (unsigned long int) random(), "1234567890123456789012345678901234567890");

    /* Now truncate it to 36 bytes and terminate. */
    memcpy(cookie, temp, 36);
    cookie[36] = '\0';
}


/* is_closed
 *
 * Test if the file descriptor fd is closed.
 * 
 * Iperf uses this function to test whether a TCP stream socket
 * is closed, because accepting and denying an invalid connection
 * in iperf_tcp_accept is not considered an error.
 */

int
is_closed(int fd)
{
    struct timeval tv;
    fd_set readset;

    FD_ZERO(&readset);
    FD_SET(fd, &readset);
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    if (select(fd+1, &readset, NULL, NULL, &tv) < 0) {
        if (errno == EBADF)
            return 1;
    }
    return 0;
}


double
timeval_to_double(struct timeval * tv)
{
    double d;

    d = tv->tv_sec + tv->tv_usec / 1000000;

    return d;
}

int
timeval_equals(struct timeval * tv0, struct timeval * tv1)
{
    if ( tv0->tv_sec == tv1->tv_sec && tv0->tv_usec == tv1->tv_usec )
	return 1;
    else
	return 0;
}

double
timeval_diff(struct timeval * tv0, struct timeval * tv1)
{
    double time1, time2;
    
    time1 = tv0->tv_sec + (tv0->tv_usec / 1000000.0);
    time2 = tv1->tv_sec + (tv1->tv_usec / 1000000.0);

    time1 = time1 - time2;
    if (time1 < 0)
        time1 = -time1;
    return time1;
}


int
delay(int64_t ns)
{
    struct timespec req, rem;

    req.tv_sec = 0;

    while (ns >= 1000000000L) {
        ns -= 1000000000L;
        req.tv_sec += 1;
    }

    req.tv_nsec = ns;

    while (nanosleep(&req, &rem) == -1)
        if (EINTR == errno)
            memcpy(&req, &rem, sizeof(rem));
        else
            return -1;
    return 0;
}

# ifdef DELAY_SELECT_METHOD
int
delay(int us)
{
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = us;
    (void) select(1, (fd_set *) 0, (fd_set *) 0, (fd_set *) 0, &tv);
    return 1;
}
#endif

/* Return the name of the interface that has iaddr IP */
char*
get_if_name(char *iaddr)
{
    char *ifname = NULL;
    int sock = 0;
    struct ifreq ifreq;
    struct if_nameindex *iflist = NULL, *listsave = NULL;
    char laddr[INET6_ADDRSTRLEN];

    //need a socket for ioctl()
    if( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("socket");
        return NULL;
    }

    //returns pointer to dynamically allocated list of structs
    iflist = listsave = if_nameindex();

    //walk thru the array returned and query for each interface's address
    for(iflist; *(char *)iflist != 0; iflist++){

        strncpy(ifreq.ifr_name, iflist->if_name, IF_NAMESIZE);
	ifreq.ifr_addr.sa_family = AF_INET;

        if(ioctl(sock, SIOCGIFADDR, &ifreq) != 0) continue;

	inet_ntop(AF_INET, (void *) &((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr, laddr, sizeof(laddr));

	mapped_v4_to_regular_v4(laddr);

        if (!strcmp(laddr, iaddr)) {
	    // FOUND!
	    int ifname_len;
	    ifname_len = strlen(ifreq.ifr_name);
	    if (ifname_len > 255) ifname_len = 255;
	    ifname = (char *)malloc(ifname_len+1);
	    strncpy(ifname, ifreq.ifr_name, ifname_len);
	    ifname[ifname_len] = (char)0;
        }
    }
    //free the dynamic memory kernel allocated for us
    if_freenameindex(listsave);
    close(sock);
    return ifname;
}

void
net_if_util(int sock_fd, int64_t pnet[NUM_NET_STATS])
{
    static char *ifname;
    static int64_t baseline[NUM_NET_STATS];

    struct timeval t_now;
    int net_pass;

    int sock_domain;
    char laddr[INET6_ADDRSTRLEN];
    socklen_t addr_len;

    if ((ifname == NULL) && (sock_fd > 0)) {  /* static i/f name for an open socket */

        sock_domain = getsockdomain(sock_fd);
        if (sock_domain == AF_INET) {
            struct sockaddr_in addr;
            addr_len = sizeof(addr);
            getsockname(sock_fd, (struct sockaddr *)&addr, &addr_len);
            inet_ntop(AF_INET, (void *) &((struct sockaddr_in *) &addr)->sin_addr, laddr, sizeof(laddr));
        } else {
            struct sockaddr_in6 addr;
            addr_len = sizeof(addr);
            getsockname(sock_fd, (struct sockaddr *)&addr, &addr_len);
            inet_ntop(AF_INET6, (void *) &((struct sockaddr_in6 *) &addr)->sin6_addr, laddr, sizeof(laddr));
        }
        mapped_v4_to_regular_v4(laddr);

        ifname = get_if_name(laddr);

    }

    /*
     * /proc/sys/net/ipv4/conf/net/<ifname>/...
     * /sys/class/net/<ifname> -> ../devices/.../net/<ifname>
     * /sys/class/net/<ifname>/statistics/{rx_bytes,rx_packets,tx_bytes,tx_packets}
     */

    if (ifname != NULL) {
		int i;
		int net_fd;

		int net_fullpathsize = 256;
		char net_fullpath[net_fullpathsize];

		int net_buflen;
		int net_bufsize = 32;
		char net_buf[net_bufsize];

		int64_t snapshot[NUM_NET_STATS];
		int64_t ss;

		/* Get snapshot of current state */
		gettimeofday(&t_now, NULL);
		snapshot[0] = t_now.tv_sec * 1000000.0 + t_now.tv_usec;
		for (net_pass = 1; net_pass < NUM_NET_STATS; net_pass++) {
		    snapshot[net_pass] = 0;
		    if ((snapshot[0] - baseline[0]) > 1000000L) {
			/* Only first time through, or more than 1s later */
			/* Allows multiple streams without redundant interface interrogation */
			net_buflen = 0;
			memset(net_fullpath, 0, net_fullpathsize);
			snprintf(net_fullpath, net_fullpathsize, "/sys/class/net/%s/statistics/%s", ifname, net_stats_label[net_pass]);
			if ((net_fd = open(net_fullpath, O_RDONLY)) >= 0) {
			    net_buflen = read(net_fd, net_buf, net_bufsize);
			    close(net_fd);
			}
			if (net_buflen > 0) {
			    ss = 0;
			    for (i = 0; (i < net_buflen) && (net_buf[i] >= '0') && (net_buf[i] <= '9'); i++) {
				ss = ss * 10 + net_buf[i] - '0';
			    }
			    snapshot[net_pass] = ss;
			}
		    }
		}

		if (baseline[0] <= 0L) { /* Timestamp */
		    /* Lock away start baseline first time through */
		    for (net_pass = 0; net_pass < NUM_NET_STATS; net_pass++) {
                        pnet[net_pass] = 0L;
                        baseline[net_pass] = snapshot[net_pass];
		    }
		} else {
		    if ((snapshot[0] - baseline[0]) > 1000000L) {
			/* Update deltas if this is more than 1s after baseline */
			for (net_pass = 0; net_pass < NUM_NET_STATS; net_pass++) {
			    if (snapshot[net_pass] >= baseline[net_pass]) {
                                pnet[net_pass] = snapshot[net_pass] - baseline[net_pass];
			    } else {
				/* Counter rollover estimation */
				int64_t net_rollover;
				for (net_rollover = pow(2,31); net_rollover >= baseline[net_pass]; net_rollover += net_rollover)
				    ;
				if ((net_rollover / 2) > baseline[net_pass]) {
				    pnet[net_pass] = 0; /* Ignore unreliable (reset? overlapped?) counter */
				} else {
				    pnet[net_pass] = net_rollover - baseline[net_pass] + snapshot[net_pass];
				}
			    }
			}
		    }
		}
    }

    /* Cleanup when final stats delivered */
    if ((sock_fd < 0) || (ifname == NULL)) {
		if (ifname != NULL)
		{
		    free(ifname);
		    ifname = (char *)0;
		}
		for (net_pass = 0; net_pass < NUM_NET_STATS; net_pass++) {
		    baseline[net_pass] = 0;
		}
    }
}


void
cpu_util(double pcpu[3])
{
    static struct timeval last;
    static clock_t clast;
    static struct rusage rlast;
    struct timeval temp;
    clock_t ctemp;
    struct rusage rtemp;
    double timediff;
    double userdiff;
    double systemdiff;

    if (pcpu == NULL) {
        gettimeofday(&last, NULL);
        clast = clock();
	getrusage(RUSAGE_SELF, &rlast);
        return;
    }

    gettimeofday(&temp, NULL);
    ctemp = clock();
    getrusage(RUSAGE_SELF, &rtemp);

    timediff = ((temp.tv_sec * 1000000.0 + temp.tv_usec) -
                (last.tv_sec * 1000000.0 + last.tv_usec));
    userdiff = ((rtemp.ru_utime.tv_sec * 1000000.0 + rtemp.ru_utime.tv_usec) -
                (rlast.ru_utime.tv_sec * 1000000.0 + rlast.ru_utime.tv_usec));
    systemdiff = ((rtemp.ru_stime.tv_sec * 1000000.0 + rtemp.ru_stime.tv_usec) -
                  (rlast.ru_stime.tv_sec * 1000000.0 + rlast.ru_stime.tv_usec));

    pcpu[0] = (((ctemp - clast) * 1000000.0 / CLOCKS_PER_SEC) / timediff) * 100;
    pcpu[1] = (userdiff / timediff) * 100;
    pcpu[2] = (systemdiff / timediff) * 100;
}

char*
get_system_info(void)
    {
    FILE* fp;
    static char buf[1000];

    fp = popen("uname -a", "r");
    if (fp == NULL)
	return NULL;
    fgets(buf, sizeof(buf), fp);
    pclose(fp);
    return buf;
    }


/* Helper routine for building cJSON objects in a printf-like manner.
**
** Sample call:
**   j = iperf_json_printf("foo: %b  bar: %d  bletch: %f  eep: %s", b, i, f, s);
**
** The four formatting characters and the types they expect are:
**   %b  boolean           int
**   %d  integer           int64_t
**   %f  floating point    double
**   %s  string            char *
** If the values you're passing in are not these exact types, you must
** cast them, there is no automatic type coercion/widening here.
**
** The colons mark the end of field names, and blanks are ignored.
**
** This routine is not particularly robust, but it's not part of the API,
** it's just for internal iperf3 use.
*/
cJSON*
iperf_json_printf(const char *format, ...)
{
    cJSON* o;
    va_list argp;
    const char *cp;
    char name[100];
    char* np;
    cJSON* j;

    o = cJSON_CreateObject();
    if (o == NULL)
        return NULL;
    va_start(argp, format);
    np = name;
    for (cp = format; *cp != '\0'; ++cp) {
	switch (*cp) {
	    case ' ':
	    break;
	    case ':':
	    *np = '\0';
	    break;
	    case '%':
	    ++cp;
	    switch (*cp) {
		case 'b':
		j = cJSON_CreateBool(va_arg(argp, int));
		break;
		case 'd':
		j = cJSON_CreateNumber(va_arg(argp, int64_t));
		break;
		case 'f':
		j = cJSON_CreateNumber(va_arg(argp, double));
		break;
		case 's':
		j = cJSON_CreateString(va_arg(argp, char *));
		break;
		default:
		return NULL;
	    }
	    if (j == NULL)
		return NULL;
	    cJSON_AddItemToObject(o, name, j);
	    np = name;
	    break;
	    default:
	    *np++ = *cp;
	    break;
	}
    }
    va_end(argp);
    return o;
}

/* Debugging routine to dump out an fd_set. */
void
iperf_dump_fdset(FILE *fp, char *str, int nfds, fd_set *fds)
{
    int fd;
    int comma;

    fprintf(fp, "%s: [", str);
    comma = 0;
    for (fd = 0; fd < nfds; ++fd) {
        if (FD_ISSET(fd, fds)) {
	    if (comma)
		fprintf(fp, ", ");
	    fprintf(fp, "%d", fd);
	    comma = 1;
	}
    }
    fprintf(fp, "]\n");
}
