/*
 * server.c 
 *
 * This file contains the server application. It simply waits for the 
 * client to send it something, which it interprets as the name of some
 * file. It then sends an OK to the client (if it can access the requested
 * file) and finally sends the file.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>

#include "mysock.h"



static char usage[] = "usage: %s \n";

static void do_connection(mysocket_t bindsd);
static int get_nvt_line(int sd, char *);
static int process_line(int sd, char *);
static int local_name(mysocket_t sd, char *name);

/**********************************************************************/
int
main(int argc, char *argv[])
{
    struct sockaddr_in sin;
    mysocket_t bindsd;
    int len, opt, errflg = 0;
    char localname[256];


    /* Parse the command line */
    while ((opt = getopt(argc, argv, "")) != EOF)
    {
        switch (opt)
        {
        case '?':
            ++errflg;
            break;
        }
    }

    if (errflg || optind != argc)
    {
        fprintf(stderr, usage, argv[0]);
        exit(EXIT_FAILURE);
    }

    /* open connection on any available port */
    if ((bindsd = mysocket()) < 0)
    {
        perror("mysocket");
        exit(EXIT_FAILURE);
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    len = sizeof(struct sockaddr_in);

    if (mybind(bindsd, (struct sockaddr *) &sin, len) < 0)
    {
        perror("mybind");
        exit(EXIT_FAILURE);
    }

    if (mylisten(bindsd, 5) < 0)
    {
        perror("mylisten");
        exit(EXIT_FAILURE);
    }
    if (local_name(bindsd, localname) < 0)
    {
        perror("local_name");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "Server's address is %s\n", localname);
    fflush(stderr);

    for (;;)
    {
        mysocket_t sd;

        /* just keep accepting connections forever */
        if ((sd = myaccept(bindsd, (struct sockaddr *) &sin, &len)) < 0)
        {
            perror("myaccept");
            exit(EXIT_FAILURE);
        }

        assert(sin.sin_family == AF_INET);
        fprintf(stderr, "connected to %s at port %u\n",
                inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

        do_connection(sd);
    }                           /* end for(;;) */

    if (myclose(bindsd) < 0)
        perror("myclose (bindsd)");
    return 0;
}

/* process a single client connection */
static void do_connection(mysocket_t sd)
{
    char line[256];
    int rc;


    /* loop over: 
       - get a request from the client
       - process the request
     */

    for (;;)
    {
        rc = get_nvt_line(sd, line);
        if (rc < 0 || !*line)
            goto done;
        fprintf(stderr, "client: %s\n", line);

        if (process_line(sd, line) < 0)
        {
            perror("process_line");
            goto done;
        }
    }   /* for (;;) */

done:
    if (myclose(sd) < 0)
    {
        perror("myclose (sd)");
    }
}


/**********************************************************************/
/* get_nvt_line
 * 
 * Retrieves the next line of NVT ASCII from mysocket layer.
 *
 * Returns 
 *  0 on success
 *  -1 on failure
 */
static int
get_nvt_line(int sd, char *line)
{
    char last_char;
    char this_char;
    int len;

    last_char = '\0';
    for (;;)
    {
        len = myread(sd, &this_char, sizeof(this_char));
        if (len < 0)
            return -1;

        if (len == 0)
        {
            /* Connection ended before line terminator (or empty string) */
            *line = '\0';
            return 0;
        }
    /** fprintf(stderr, "read character %c\n", this_char); **/
        if (last_char == '\r' && this_char == '\n')
        {
            /* Reached the end of line. Already wrote \r into string, overwrite
             * it with a NUL */
            line[-1] = '\0';
            return 0;
        }

        *line++ = this_char;
        last_char = this_char;
    }
    return -1;
}

/**********************************************************************/
/* process_line
 * 
 * Process the request (a filename) from the client. Send back the
 * response and then the content of the requested file through
 * mysocket layer.
 *
 * Returns 
 *  0 on success
 *  -1 on failure
 */
static int
process_line(int sd, char *line)
{
    char resp[5000];
    int fd = -1, length;

    if (!*line || access(line, R_OK) < 0)
    {
        sprintf(resp, "%s,-1,File does not exist or access denied\r\n", line);
    }
    else
    {
        if ((fd = open(line, O_RDONLY)) < 0)
        {
            sprintf(resp, "%s,-1,File could not be opened\r\n", line);
        }
        else
        {
            sprintf(resp, "%s,%lu,Ok\r\n", line, lseek(fd, 0, SEEK_END));
            lseek(fd, 0, SEEK_SET);
        }
    }
  /** fprintf(stderr, "sending to client: %s of length %d bytes\n", resp, strlen(resp)); **/
    /* Return the response to the client */
    if (mywrite(sd, resp, strlen(resp)) < 0)
    {
        if (fd != -1)
            close(fd);
        return -1;
    }

    if (fd == -1)
        return 0;

    for (;;)
    {
        length = read(fd, resp, sizeof(resp));
        if (length == 0)
            break;

        if (length == -1)
        {
            perror("read");
            close(fd);
            return -1;
        }

        /* fwrite(resp, length, 1, stdout); */

        if (mywrite(sd, resp, length) < 0)
        {
            close(fd);
            return -1;
        }
    }

    close(fd);
    return 0;
}

/* local_name()
 *
 * Takes in a mysocket descriptor and finds the (local_addr, local_port)
 * associated with sd. It places into name a string of the form
 * "hostname:portname"; name must have memory allocated already.
 *
 * XXX: This is broken on multi-homed hosts (e.g. VNS).
 *
 * Returns 0 on success and -1 on failure.
 */

static int local_name(mysocket_t sd, char *name)
{
#define MAX_HOSTNAMELEN 100

    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);
    char myhostname[MAX_HOSTNAMELEN];

    assert(name);

    /* get local port associated with the mysocket */
    if (mygetsockname(sd, (struct sockaddr *) &sin, &sin_len) < 0)
    {
        assert(0);
        return -1;
    }

    /* get name of current host */
    if (gethostname(myhostname, sizeof(myhostname)) < 0)
    {
        assert(0);
        return -1;
    }

    sprintf(name, "%s:%u", myhostname, ntohs(sin.sin_port));
    return 0;
}

