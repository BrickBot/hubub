/**
 *  Copyright (c) 2000 Mark Anacker  All rights reserved.
 *
 *  piper1.c - TCP-based network client - part of the "hubub" project
 *  by Mark Anacker  12/15/2000
 *
 * The "hubub" project, including all files needed to compile it,
 * is free software; you can redistribute it and/or use it and/or 
 * modify it under the terms of the "Artistic License".
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the "Artistic License"
 * along with this program.
 *
 *  $Author: manacker $
 *  $Date: 2000/12/19 06:48:38 $
 *  $Header: /cvsroot/hubub/hubub/hubub1/piper1/piper1.c,v 1.1.1.1 2000/12/19 06:48:38 manacker Exp $
 *  $Id: piper1.c,v 1.1.1.1 2000/12/19 06:48:38 manacker Exp $
 *  $Name:  $
 *  $Revision: 1.1.1.1 $
 *  $Source: /cvsroot/hubub/hubub/hubub1/piper1/piper1.c,v $
 *  $State: Exp $
 *  $Log: piper1.c,v $
 *  Revision 1.1.1.1  2000/12/19 06:48:38  manacker
 *  Initial checkin
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

#ifndef WIN32
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <netdb.h>
   #include <unistd.h>
   #include <sys/time.h>
   #include <syslog.h>
   #include <sys/ioctl.h>
   #include <termios.h>
#else
   #include <winsock.h>
#endif

#define  BUFFERSIZE        4096  /* default data buffer size */
#define  TCPBUFSIZE        32768 /* default socket buffer size */

/* fdsets we can monitor */
#define  FD_IS_READABLE    0
#define  FD_IS_WRITEABLE   1
#define  FD_IS_EXCEPTION   2

/* return codes */
#define  ERROR_RET         -1
#define  NEUTRAL_RET       0
#define  GOOD_RET          1

#ifdef WIN32
   #define  NH_BAD_SOCKET  INVALID_SOCKET
   #define  POLL_TIMEOUT   1000  /* check for termination every second */
#else
   #define  SOCKET         int
   #define  NH_BAD_SOCKET  -1
   #define  POLL_TIMEOUT   500   /* check for signals every .5 seconds */
#endif

#ifndef WIN32
extern int errno;
struct termios saved_attributes;
int            saved_attributes_flag = 0;
#endif

/* ================================================================================== */

/* command-line parameters */
char     *serverName;
int      port = 0;                  /* server port */
int      bufferSize = BUFFERSIZE;   /* data buf size */
int      rcvBufSize = TCPBUFSIZE;   /* socket recv buffer size */
int      sndBufSize = TCPBUFSIZE;   /* socket send buffer size */
int      verboseFlag = 0;           /* extra run-time verbosity */
int      linemodeFlag = 0;          /* if set, turns on cooked mode */

/* file descriptor structs */
fd_set   master_rfdset;
fd_set   master_wfdset;
fd_set   master_efdset;
   
fd_set   working_rfdset;
fd_set   working_wfdset;
fd_set   working_efdset;

SOCKET   clientSocket;        /* client socket */
int      runFlag = 0;

int      maxfd = 0;           /* maxfd value for select */
char     *bufP = NULL;        /* message buffer */

/* ================================================================================== */

/* ---------------------------------------------------------------------------------- */
/* global functions                                                                   */
/* ---------------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------------------
 * init()
 * 
 * bufferSize  The size in bytes of the data buffer
 * 
 * returns:    nothing
 *
 * Creates the data buffer, sets up warious stuff.
 ------------------------------------------------------------------------------------ */
void
init(void)
{

#ifdef WIN32
/* if we're using Windows, we have to go and init Winsock */
WORD    wVersionRequested;
WSADATA wsaData;

   /* request version 2.2 */
   wVersionRequested = MAKEWORD( 2, 2 );

   /* turn the key and see if she starts... */
   if (WSAStartup(wVersionRequested, &wsaData) != 0) 
   {
      /* Tell the user that we could not find a usable      */
      /* WinSock DLL.                                       */
      fprintf(stderr, "ERR: Couldn't start Winsock.\n");
      return;
   }
 
   /* Confirm that the WinSock DLL supports 2.2.            */
   /* Note that if the DLL supports versions greater        */
   /* than 2.2 in addition to 2.2, it will still return     */
   /* 2.2 in wVersion since that is the version we          */
   /* requested.                                            */
 
   if ( LOBYTE( wsaData.wVersion ) != 2 ||
        HIBYTE( wsaData.wVersion ) != 2 ) 
   {
      /* Tell the user that we could not find a usable      */
      /* WinSock DLL.                                       */
      fprintf(stderr, "ERR: Winsock version isn't 2.2 or better.\n");
      return;
   }
   /* The WinSock DLL is acceptable.                        */
#endif

   /* allocate a buffer for our network data */
   bufP = (char *) calloc(1, (bufferSize+1));
   if (bufP == NULL)
   {
      fprintf(stderr, "ERR: Couldn't alloc memory for data buffer.\n");
   }
   else
      runFlag = 1;   /* signal everything is okay so far */
}

/* ------------------------------------------------------------------------------------
 * deinit()
 * 
 * returns:    nothing
 *
 * Cleans up after we're done running - frees buffers, etc.
 ------------------------------------------------------------------------------------ */
void
deinit(void)
{
   /* if we had a listening socket running */
   if (clientSocket != -1)
   {
      shutdown(clientSocket, 2);
#ifdef WIN32
      closesocket(clientSocket);
      WSACleanup();
#else
      close(clientSocket);
#endif
   }
   
   /* and the data buffer */
   if (bufP != NULL)
      free(bufP);
}

/* ---------------------------------------------------------------------------------- */
/* FDSET manipulation functions                                                       */
/* ---------------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------------------
 * fd_clear()
 * 
 * returns:    nothing
 *
 * Clears out the master fdsets
 ------------------------------------------------------------------------------------ */
void
fd_clear(void)
{
   FD_ZERO(&master_rfdset);
   FD_ZERO(&master_wfdset);
   FD_ZERO(&master_efdset);
   maxfd = -1;
}

/* ------------------------------------------------------------------------------------
 * fd_add()
 * 
 * fd          The i/o descriptor to add
 * set         The specific master fdset to add it to
 * 
 * returns:    nothing
 *
 * Adds a given i/o descriptor (file, socket, etc) to one of the master fdsets.
 ------------------------------------------------------------------------------------ */
void
fd_add(int fd, int set)
{
#ifdef WIN32
   u_int tfd = fd;
#else
   int tfd = fd;
#endif

   switch(set)
   {
      case FD_IS_WRITEABLE:
                           FD_SET(tfd, &master_wfdset);
                           break;
      case FD_IS_READABLE:
                           FD_SET(tfd, &master_rfdset);
                           break;
      case FD_IS_EXCEPTION:
                           FD_SET(tfd, &master_efdset);
                           break;
   }
   /* set our max fd for the select */
   if (fd > maxfd)
      maxfd = fd;
}

/* ------------------------------------------------------------------------------------
 * fd_del()
 * 
 * fd          The i/o descriptor to remove
 * set         The specific master fdset to remove it from
 * 
 * returns:    nothing
 *
 * Removes a given i/o descriptor (file, socket, etc) from one of the master fdsets.
 ------------------------------------------------------------------------------------ */
void
fd_del(int fd, int set)
{
#ifdef WIN32
   u_int tfd = fd;
#else
   int tfd = fd;
#endif

   switch(set)
   {
      case FD_IS_WRITEABLE:
                           FD_CLR(tfd, &master_wfdset);
                           break;
      case FD_IS_READABLE:
                           FD_CLR(tfd, &master_rfdset);
                           break;
      case FD_IS_EXCEPTION:
                           FD_CLR(tfd, &master_efdset);
                           break;
   }
}

/* ------------------------------------------------------------------------------------
 * fd_select()
 * 
 * time_msecs  The maximum time we will wait (in milliseconds) for activity before
 *             returning.  If this value is 0, we immediately return after checking
 *             the i/o status (polling).  If the value is <0, we wait indefinitely
 *             for activity on one of the descriptors.
 * 
 * returns:    The number of descriptors that we have to check (>0) if i/o or an
 *                exception occurred on one of them.
 *             NEUTRAL_RET if we timed out without anything happening
 *             ERROR_RET if an error occurred.
 *
 * Here we call the OS select() to check the master fdsets (populated with fd_add())
 * for activity.  If anything happend on the monitored descriptors, the matching
 * entry will be set in the working fdsets, and can be tested for with fd_check().
 ------------------------------------------------------------------------------------ */
int
fd_select(long time_msecs)
{
   struct timeval timeout;

   /* copy the master fdsets to working copies */
   memcpy(&working_rfdset, &master_rfdset, sizeof(master_rfdset));
   memcpy(&working_wfdset, &master_wfdset, sizeof(master_wfdset));
   memcpy(&working_efdset, &master_efdset, sizeof(master_efdset));

   /* they want a timeout */
   if (time_msecs > 0)
   {
      timeout.tv_sec = time_msecs / 1000L;
      timeout.tv_usec = (time_msecs % 1000L) * 1000L;
      return (select(maxfd+1, &working_rfdset, &working_wfdset, &working_efdset, &timeout));
   }
   else
   /* they want to poll */
   if (time_msecs == 0)
   {
      timeout.tv_sec = 0L;
      timeout.tv_usec = 0L;
      return (select(maxfd+1, &working_rfdset, &working_wfdset, &working_efdset, &timeout));
   }
   else
   /* they want to block until something happens */
      return (select(maxfd+1, &working_rfdset, &working_wfdset, &working_efdset, NULL));
}

/* ------------------------------------------------------------------------------------
 * fd_check()
 * 
 * fd          The i/o descriptor to test
 * set         The specific working fdset to check
 * 
 * returns:    NEUTRAL_RET if the descriptor is not in the set
 *             != 0 if it *is* set
 *
 * Checks an i/o descriptor against a *working* fdset to see if it's in that set.  Note
 * that we're testing the working_ fdsets here, not the master ones (as in the fd_add(),
 * fd_del(), and fd_clear() functions).  So the results of this function are only
 * valid *after* a call to fd_select(), which actually popoulates working fdsets.
 ------------------------------------------------------------------------------------ */
int
fd_check(int fd, int set)
{
#ifdef WIN32
   u_int tfd = fd;
#else
   int tfd = fd;
#endif

   switch(set)
   {
   case FD_IS_WRITEABLE:
                        return (FD_ISSET(tfd, &working_wfdset));
   case FD_IS_READABLE:
                        return (FD_ISSET(tfd, &working_rfdset));
   case FD_IS_EXCEPTION:
                        return (FD_ISSET(tfd, &working_efdset));
   }
   return 0;
}

/* ---------------------------------------------------------------------------------- */
/* client network functions                                                           */
/* ---------------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------------------
 * nuke_socket()
 * 
 * s           The socket to dispose
 * 
 * returns:    nothing
 *
 * Make sure a socket is properly disposed of.  This includes shutting it down (with
 * no further sends or receives allowed), then closing it.
 ------------------------------------------------------------------------------------ */
void
nuke_socket(SOCKET s)
{
   shutdown(s, 2);
#ifdef WIN32
   closesocket(s);
   WSACleanup( );
#else
   close(s);
#endif
}

/* ------------------------------------------------------------------------------------
 * set_nonblocking_mode()
 * 
 * s           The socket to set
 * 
 * returns:    GOOD_RET if the mode set succeeded
 *             ERROR_RET if there was a fatal error
 *
 * Set the socket to non-blocking (and in the case of Unix, no-delay) mode.
 ------------------------------------------------------------------------------------ */
int
set_nonblocking_mode(int fd)
{
#ifdef WIN32
u_long               lArg = 1;
#else
int                  flags = 0;
#endif

   /* set the file descriptor to no-delay, non-blocking mode */
#ifdef WIN32
   ioctlsocket(fd, FIONBIO, (u_long FAR *) &lArg);
#endif
#ifndef WIN32
   flags = fcntl(fd, F_GETFL, 0);
   if (flags == ERROR_RET)
   {
      return(ERROR_RET);
   }
   if (fcntl(fd, F_SETFL, flags | O_NDELAY | O_NONBLOCK) < 0)
   {
      return(ERROR_RET);
   }
#endif

   return(GOOD_RET);
}

/* ------------------------------------------------------------------------------------
 * start_listener()
 * 
 * addr        The address or host name of the server to contact
 * port        The port to connect to
 * 
 * returns:    NEUTRAL_RET if all went well
 *             ERROR_RET if there was a fatal error
 *
 * Creates a client socket and connects it to the server.  It also sets a
 * number of the modes, and the network buffers sizes.
 ------------------------------------------------------------------------------------ */
int
start_client(char *addr, int port)
{
struct sockaddr_in   svraddr;
struct hostent*      pHost = NULL;
u_long               lTmpAddr;
struct linger        sLinger;
int                  iArg;
char                 options[5];

   /* make the socket */
   clientSocket = socket(PF_INET, SOCK_STREAM, 0);

   svraddr.sin_family = PF_INET;
   svraddr.sin_port = htons(port);

   /* first, see if they gave us a dotted-quad (n.n.n.n) */
#ifdef SUNOS
   if ((lTmpAddr=inet_addr(addr)) != (in_addr_t) -1)
#else
   if ((lTmpAddr=inet_addr(addr)) != INADDR_NONE)
#endif
   {
      svraddr.sin_addr.s_addr = lTmpAddr;
   }
   else  /* nope, try to resolve the host name */
   {
      pHost = gethostbyname(addr);
      if (!pHost) /* not found */
      {
         return(ERROR_RET);
      }
      else
      {
         memcpy(&svraddr.sin_addr.s_addr, pHost->h_addr, sizeof(long));
      }
   }

   /* set receive buffer size */
   iArg = rcvBufSize;
   setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, (char *) &iArg, sizeof(int));
   /* set send buffer size */
   iArg = sndBufSize;
   setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, (char *) &iArg, sizeof(int));

   /* connect it */
   if (connect(clientSocket, (struct sockaddr *)&svraddr, sizeof(struct sockaddr)) < 0)
   {
      fprintf(stderr, "ERR: Connect failed.\n");
      return(ERROR_RET);
   }

   /* turn linger on for 1 second */
   sLinger.l_onoff = 1;
   sLinger.l_linger = 1;
   setsockopt(clientSocket, SOL_SOCKET, SO_LINGER, (char *) &sLinger, sizeof(sLinger));

   /* turn keep-alive on */
   options[0] = (char) 1;
   setsockopt(clientSocket, SOL_SOCKET, SO_KEEPALIVE, (char *) &options, sizeof(int));

   /* set the socket to no-delay mode */
   if (set_nonblocking_mode(clientSocket) == ERROR_RET)
   {
      nuke_socket(clientSocket);
      return(ERROR_RET);
   }

   /* set up the select FD set */
   fd_clear();
   fd_add(clientSocket, FD_IS_READABLE);

   return(NEUTRAL_RET);
}

/* ------------------------------------------------------------------------------------
 * check_client()
 * 
 * s           The client socket to check
 * 
 * returns:    GOOD_RET if data is waiting on this socket
 *             NEUTRAL_RET when no data, but no error either
 *             ERROR_RET if there was a fatal error
 *
 * Check a client socket for readable or error condition
 ------------------------------------------------------------------------------------ */
int
check_client(SOCKET s)
{

#ifdef xxxx
char buf;

   /* check for errors */
   if (fd_check(s, FD_IS_EXCEPTION))
   {
      /* do the readability test - peek 1 byte */
      if (recv (s, &buf, 1, MSG_PEEK) < 0)
      {
#ifdef WIN32
         return(ERROR_RET);
#else
         if (errno != EAGAIN)  /* ignore EAGAIN */
            return(ERROR_RET);
#endif
      }
   }
#endif

   /* check for data waiting */
   if (fd_check(s, FD_IS_READABLE))
   {
      return(GOOD_RET);
   }
   
   return(NEUTRAL_RET);
}

/* ------------------------------------------------------------------------------------
 * bytes_avail()
 * 
 * s           The client socket to check
 * 
 * returns:    the number of bytes waiting to be read on the client socket
 *             ERROR_RET if there was a fatal error
 *
 * Return the count of bytes waiting on a socket
 ------------------------------------------------------------------------------------ */
int
bytes_avail(SOCKET s)
{
int      bytesThere = 0;
int      rv;
#ifdef WIN32
u_long   lArg = 0;
#endif

#ifdef WIN32
   rv = ioctlsocket(s, FIONREAD, &lArg);
   bytesThere = lArg;
#else
   rv = ioctl(s, FIONREAD, &bytesThere);
#endif

   if (rv < 0)
      return(ERROR_RET);
   else
      return(bytesThere);
}

/* ------------------------------------------------------------------------------------
 * recv_msg()
 * 
 * s           The socket to read from
 * 
 * returns:    The result from the recv() call (if >= 0, the number of bytes read into
 *             the data buffer).  -1 if there was a fatal error.
 *
 * Reads from the socket into the shared data buffer.
 ------------------------------------------------------------------------------------ */
int
recv_msg(SOCKET source)
{
   return(recv(source, bufP, (int) bufferSize, 0));
}

/* ------------------------------------------------------------------------------------
 * send_msg()
 * 
 * s           The socket to send to
 * msglen      The number of bytes to write from the buffer
 * 
 * returns:    nothing
 *
 * Write from the shared data buffer to the socket.
 ------------------------------------------------------------------------------------ */
int
send_msg(int msgLen)
{
   /* let's do some simple checks first */
   if (msgLen < 1)
      return(GOOD_RET);
      
   /* if it's live, and not the source of the message */
   if (clientSocket != -1 )
   {
      /* try to write to it */
      if (send(clientSocket, bufP, msgLen, 0) < 0)
      {
         /* errors mean the death of the client */
         return(ERROR_RET);
      }
   }

   return(GOOD_RET);
}

/* ---------------------------------------------------------------------------------------
 * poll_network()
 * 
 * See if we have any data waiting to be read on our socket or stdin
 * 
 * timeout  time to wait if nothing is available (<0 == block until data is ready,
 *          0 == don't block at all, >0 == wait timeout in millisecs)
 * 
 * returns:
 *       if successful, returns the socket id
 *       NEUTRAL_RET on timeout with no data available
 *       ERROR_RET on failure
 * ---------------------------------------------------------------------------------------
 */
int 
poll_network(long timeout)
{
int      rv;
int      bytesRead;

   rv = fd_select(timeout);
   if (rv > 0)
   {
      /* data on stdin */
      if (fd_check(STDIN_FILENO, FD_IS_READABLE))
      {
         bytesRead = read(STDIN_FILENO, bufP, BUFFERSIZE);
         /* if no errors, and we read something */
         if (bytesRead > 0)
         {
            if (send_msg(bytesRead) == ERROR_RET)
               return(ERROR_RET);
         }
      } /* if (fd_check(STDIN_FILENO, FD_IS_READABLE)) */

      /* check the socket for a readable condition */
      if (check_client(clientSocket) != ERROR_RET)
      {
         /* check the contents of the socket */
         if (bytes_avail(clientSocket) > 0)
         {
            /* try and read some of the data */
            if ((bytesRead=recv_msg(clientSocket)) < 0)
               return(ERROR_RET);

            /* if no errors, and we got something */
            if (bytesRead > 0)
            {
               /* spit it out */
               write(STDOUT_FILENO, bufP, bytesRead);
            }
         }
      } /* if (check_client(clientSocket) != ERROR_RET) */
   }
   else
   if (rv == 0)
   {
      /* timer expired */
      return(NEUTRAL_RET);
   }
   /* check for a possible error state */
   if ((errno == EAGAIN) || (errno == 0))
      /* oh no, not eagain again... ignore it */
      return(NEUTRAL_RET);
   else
      /* otherwise, an error */
      return(ERROR_RET);
}

/* ================================================================================== */

/* ---------------------------------------------------------------------------------- */
/* client functions                                                                   */
/* ---------------------------------------------------------------------------------- */

#ifndef WIN32
/* ------------------------------------------------------------------------------------
 * reset_input_mode()
 * 
 * returns:    nothing
 *
 * Resets stdin to the mode it was before
 ------------------------------------------------------------------------------------ */
void 
reset_input_mode(void)
{
   if (saved_attributes_flag)
      tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);
}

/* ------------------------------------------------------------------------------------
 * set_input_mode()
 * 
 * returns:    nothing
 *
 * If stdin is a terminal, and they didn't ask for linemode (-l), we switch to raw
 * input mode (non-canonical, no-echo).  
 ------------------------------------------------------------------------------------ */
void 
set_input_mode(void)
{
struct termios tattr;

   /* see if stdin is a terminal. */
   if (!isatty(STDIN_FILENO))
   {
      /* and don't do this if it isn't */
      return;
   }

   /* Save the terminal attributes so we can restore them later. */
   tcgetattr(STDIN_FILENO, &saved_attributes);

   /* Set the funny terminal modes. */
   tcgetattr(STDIN_FILENO, &tattr);
   tattr.c_lflag &= ~(ICANON|ECHO); /* Clear ICANON and ECHO. */
   tattr.c_cc[VMIN] = 1;
   tattr.c_cc[VTIME] = 0;
   tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr);
   /* say we were here */
   saved_attributes_flag = 1;
}
#endif

/* ------------------------------------------------------------------------------------
 * useage()
 * 
 * appName     The program name from argv[0]
 * 
 * returns:    nothing
 *
 * Print program useage message.
 ------------------------------------------------------------------------------------ */
void
useage(char *appName)
{
   printf("%s: options:\n", appName);
   printf("       -h          this help message\n");
   printf("       -l          buffered line input mode\n");
   printf("       -v          verbose mode\n");
   printf("       -b <bytes>  buffer size in bytes (default=%d)\n", BUFFERSIZE);
   printf("       -s <addr>   server to connect to (*REQUIRED*)\n");
   printf("       -p <port>   port to connect to (*REQUIRED*)\n");
   printf("       -r <bytes>  socket recv buffer in bytes (default=%d)\n", BUFFERSIZE);
   printf("       -t <bytes>  socket send buffer in bytes (default=%d)\n", BUFFERSIZE);
}

/* ------------------------------------------------------------------------------------
 * signal_handler()
 * 
 * sig         The Unix signal we were passed
 * 
 * returns:    nothing
 *
 * There is only one response to a trapped signal - flag for exit.
 ------------------------------------------------------------------------------------ */
void
signal_handler(int sig)
{
   runFlag = 0;
#ifndef WIN32
   reset_input_mode();
#endif
}

/* ------------------------------------------------------------------------------------
 * main()
 * 
 ------------------------------------------------------------------------------------ */
int
main(int argc, char **argv)
{
int   rv = 0;
int   c;

   opterr = 0;
   while ((c = getopt(argc, argv, "hlvs:b:p:r:t:")) != -1)
   {
      switch (c)
      {
         case 'h':
                     useage(argv[0]);
                     exit(1);
                     break;
         case 'l':
                     linemodeFlag = 1;
                     break;
         case 'v':
                     verboseFlag = 1;
                     break;
         case 'b':
                     bufferSize = atoi(optarg);
                     break;
         case 'p':
                     port = atoi(optarg);
                     break;
         case 's':
                     serverName = optarg;
                     break;
         case 'r':
                     rcvBufSize = atoi(optarg);
                     break;
         case 't':
                     sndBufSize = atoi(optarg);
                     break;
         case '?':
                     fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                     useage(argv[0]);
                     exit(1);
         default:
                     useage(argv[0]);
                     exit(1);
      }
   }

   if ( (serverName == NULL) || (port == 0) )
   {
      fprintf(stderr, "ERR: missing server address or bad port number: %s %d\n", serverName, port);
      exit(1);
   }

   if ( (bufferSize <= 0) )
   {
      fprintf(stderr, "ERR: invalid buffer size: %d\n", bufferSize);
      exit(1);
   }

   /* set up globals */
   init();

   /* if we're good to go... */
   if (runFlag)
   {

#ifndef WIN32
      /* establish our signal handlers for a clean exit */
      signal(SIGTERM, signal_handler);
      signal(SIGHUP, signal_handler);
      signal(SIGINT, signal_handler);
#endif
     
      /* create and configure listener socket */
      if (start_client(serverName, port) != ERROR_RET)
      {
         if (set_nonblocking_mode(STDIN_FILENO) != ERROR_RET)
         {
#ifndef WIN32
            if (!linemodeFlag)
               set_input_mode();
#endif
            fd_add(STDIN_FILENO, FD_IS_READABLE);

            /* main loop */
            while (runFlag)
            {
               /* poll and process network traffic until we error out */
               if (poll_network(POLL_TIMEOUT) == ERROR_RET)
                  runFlag = 0;
            } /* while (runFlag) */
         } /* if (set_nonblocking_mode(STDIN_FILENO) != ERROR_RET) */
      } /* if (start_client(serverName, port) != ERROR_RET) */
      else
      {
         fprintf(stderr, "Fatal error connecting to server: %s %d\n", serverName, port);
         rv = 1;
      }
   } /* if (runFlag) */

#ifndef WIN32
   reset_input_mode();
#endif

   /* cleanup */
   deinit();      

   return(rv);
}
