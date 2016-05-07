/*
 * client.c 
 *
 *
 * This file contains the client application. In the interactive
 * mode, it waits for the user
 * to type the name of a file. This filename is sent to the running 
 * server which then replies with the contents of the file. In the 
 * non-iteractive mode (when the option '-f' is specified along with
 * a filename) it simply asks for that file from the server and exits.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#ifdef LINUX
#include <unistd.h> /*getopt*/
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "mysock.h"

/* Every received file is stored with this filename */
#define RCVD_FILENAME "rcvd"

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

static char usage[] = "usage: client [-q] [-f <filename>] server:port\n";
static char *filename;
static int quiet_opt = 0;

static int parse_address(char *address, struct sockaddr_in *sin);
static int get_nvt_line(int sd, char *line);
static void loop_until_end(int sd);


/**********************************************************************/
int
main(int argc, char *argv[])
{
    struct sockaddr_in sin;
    char opt;
    char *pline;
    int errflg = 0;
    int sd;



    filename = NULL;
    /* Parse command line options */
    while ((opt = getopt(argc, argv, "f:q")) != EOF)
    {
        switch (opt)
        {
        case 'f':
            filename = optarg;
            break;
        case 'q':
            ++quiet_opt;
            break;
        case '?':
            ++errflg;
            break;
        }
    }

    if (errflg || optind != argc - 1)
    {
        fputs(usage, stderr);
        exit(1);
    }

    pline = argv[optind];

    if (parse_address(pline, &sin) < 0)
    {
        perror("parse_address");
        exit(1);
    }

    if (!sin.sin_port)
    {
        fprintf(stderr, "Format is %s server:port\n", argv[0]);
        exit(1);
    }

    if ((sd = mysocket()) < 0)
    {
        perror("mysocket");
        exit(1);
    }

    sd = myconnect(sd, (struct sockaddr *) &sin, sizeof(struct sockaddr_in));
    if (sd < 0)
    {
        perror("myconnect");
        exit(1);
    }

    loop_until_end(sd);

    if (myclose(sd) < 0)
    {
        perror("myclose");
    }

    return 0;
}                               /* end main() */


/**********************************************************************/
/* loop_until_end
 * 
 * Loop until the connection has closed
 */
void
loop_until_end(int sd)
{
    int errcnd;
    char line[1000];
    int length, to_read;
    char *pline, *lenstr, *resp;
    int got;
    FILE *file;

    for (;;)
    {

        errcnd = 0;
        if (filename == NULL)
        {
            /* Prompt for a request to the server (a filename) */
            printf("\nclient> ");
            fflush(stdout);
            if (!fgets(line, sizeof(line), stdin))
                break;

            /* Remove trailing spaces and add CRLF at the end */
            pline = line + strlen(line) - 1;
            while ((pline > line - 1) && isspace((int) (*pline)))
                --pline;

            if (pline <= line)
                continue;
        }
        else
        {
            strcpy(line, filename);
            pline = line + strlen(line) - 1;
        }
        *++pline = '\r';
        *++pline = '\n';
        *++pline = '\0';

        if (mywrite(sd, line, pline - line) < 0)
        {
            perror("mywrite");
            errcnd = 1;
            break;
        }

        if (get_nvt_line(sd, line) < 0)
        {
            perror("get_nvt_line");
            errcnd = 1;
            break;
        }

        printf("server: %s\n", line);
        fflush(stdout);

        /* Parse the response from the server */
        if (NULL == (resp = strrchr(line, ',')))
        {
            fprintf(stderr, "Malformed response from server.\n");
            errcnd = 1;
            break;
        }
        *resp++ = '\0';

        if (NULL == (lenstr = strrchr(line, ',')))
        {
            fprintf(stderr, "Malformed response from server.\n");
            errcnd = 1;
            break;
        }
        *lenstr++ = '\0';


        sscanf(lenstr, "%d", &length);
        if (length == -1)
        {
            /* Error reported from server */
            if (filename == NULL)
                continue;
            else
            {
                errcnd = 1;
                break;
            }

        }
        if ((file = fopen(RCVD_FILENAME, "w")) == NULL)
        {
            perror("file_to_write error");
            errcnd = 1;
            break;
        }
        /* Retrieve the remote file and write it to a local file */
        while (length)
        {
            to_read = MIN(length, (int) sizeof(line));

            if ((got = myread(sd, line, to_read)) < 0)
            {
                perror("myread");
                errcnd = 1;
                break;
            }

            if (!got)
            {
                break;
            }

            if (got < to_read)
            {
                to_read = got;
            }

            if (!quiet_opt)
            {
                while (0 == fwrite(line, 1, to_read, file))
                {
                    if (errno != EINTR)
                    {
                        perror("fwrite");
                        errcnd = 1;
                        break;
                    }
                }
            }
            length -= to_read;
        }

        if (length)
        {
            fprintf(stderr,
                    "Exiting: read bad number of bytes (%d less than expected)...\n",
                    length);
            fclose(file);
            myclose(sd);
            exit(-1);
        }

        fclose(file);
        if (filename != NULL)
            break;

    }                           /* end for(;;) */

    if (errcnd) fprintf(stderr, "An error occurred\n");
}

/**********************************************************************/
/* parse_address
 *
 * Get the address and write it in the appropiate format to "sin"
 */
int
parse_address(char *address, struct sockaddr_in *sin)
{
    char *address_copy = NULL;
    char *pc;
    unsigned h_port;
    int rc = -1;
    struct hostent *he;

    if (NULL == (address_copy = strdup(address)))
        goto cleanup;

    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;

    if (NULL == (pc = strchr(address_copy, ':')))
    {
        sin->sin_port = 0;
    }
    else
    {
        if (1 != sscanf(pc + 1, "%u", &h_port))
        {
            errno = EINVAL;
            goto cleanup;
        }

        sin->sin_port = htons(h_port);
        *pc = '\0';
    }

    if ((in_addr_t) - 1 == (sin->sin_addr.s_addr = inet_addr(address_copy)))
    {
        if (NULL == (he = gethostbyname(address_copy)) ||
            he->h_addrtype != AF_INET || he->h_length != 4)
        {
            errno = EADDRNOTAVAIL;
            goto cleanup;
        }

        memcpy((char *) &sin->sin_addr, he->h_addr, sizeof(sin->sin_addr));
    }

    rc = 0;

cleanup:
    if (address_copy)
        free(address_copy);

    return rc;
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
}
