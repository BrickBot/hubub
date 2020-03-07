/**
 *  Copyright (c) 2000 Mark Anacker  All rights reserved.
 *
 *  hubub1.c - TCP-based network data hub
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
 *  $Date: 2000/12/19 06:48:29 $
 *  $Header: /cvsroot/hubub/hubub/hubub1/hubub1.c,v 1.1.1.1 2000/12/19 06:48:29 manacker Exp $
 *  $Id: hubub1.c,v 1.1.1.1 2000/12/19 06:48:29 manacker Exp $
 *  $Name:  $
 *  $Revision: 1.1.1.1 $
 *  $Source: /cvsroot/hubub/hubub/hubub1/hubub1.c,v $
 *  $State: Exp $
 *  $Log: hubub1.c,v $
 *  Revision 1.1.1.1  2000/12/19 06:48:29  manacker
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
#else
   #include <winsock.h>
#endif

#define  CLIENTMAX         16    /* default number of simultaneous clients */
#define  BUFFERSIZE        4096  /* default data buffer size */
#define  TCPBUFSIZE        32768 /* default socket buffer size */

#define  LISTENBACKLOG  5        /* number of client connects we can have queued */

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
#endif

/* ================================================================================== */

/* command-line parameters */
int      port = 0;                  /* server port */
int      bufferSize = BUFFERSIZE;   /* data buf size */
int      maxClients = CLIENTMAX;    /* maximum number of simultaneous clients */
int      rcvBufSize = TCPBUFSIZE;   /* socket recv buffer size */
int      sndBufSize = TCPBUFSIZE;   /* socket send buffer size */
int      verboseFlag = 0;           /* extra run-time verbosity */

/* file descriptor structs */
fd_set   master_rfdset;
fd_set   master_wfdset;
fd_set   master_efdset;
   
fd_set   working_rfdset;
fd_set   working_wfdset;
fd_set   working_efdset;

SOCKET   listenSocket;        /* listening socket */
int      runFlag = 0;

int      maxfd = 0;           /* maxfd value for select */
int      clientCount = 0;     /* current number of clients */
int      topClient= 0;        /* highest-numbered client table slot we've used */
SOCKET   *socketTable;        /* socket table */
char     *bufP = NULL;        /* pointer to the data buffer */
 
/* ================================================================================== */

/* ---------------------------------------------------------------------------------- */
/* global functions                                                                   */
/* ---------------------------------------------------------------------------------- */

#ifdef WIN32
   #include "getopt.c"
#endif

/* ------------------------------------------------------------------------------------
 * init()
 * 
 * returns:    nothing
 *
 * Sets up the various tables, buffers, whatever, and then sets the global variable
 * runFlag if everything went okay.
 ------------------------------------------------------------------------------------ */
void
init()
{
int   slot;

#ifdef WIN32
/* if we're using Windows, we have to go and init Winsock */
WORD    wVersionRequested;
WSADATA wsaData;

   /* request version 2.2 */
   wVersionRequested = MAKEWORD( 2, 2 );

   /* turn the key and see if she starts... */
   if (WSAStartup(wVersionRequested, &wsaData) != 0)
   {
      /* Tell the user that we could not find a usable   */
      /* WinSock DLL.                                    */
      fprintf(stderr, "ERR: Couldn't start Winsock.\n");
      return;
   }
 
   /* Confirm that the WinSock DLL supports 2.2.         */
   /* Note that if the DLL supports versions greater     */
   /* than 2.2 in addition to 2.2, it will still return  */
   /* 2.2 in wVersion since that is the version we       */
   /* requested.                                         */
 
   if ( LOBYTE( wsaData.wVersion ) != 2 ||
        HIBYTE( wsaData.wVersion ) != 2 ) 
   {
      /* Tell the user that we could not find a usable   */
      /* WinSock DLL.                                    */
      fprintf(stderr, "ERR: Winsock version isn't 2.2 or better.\n");
      return;
   }

   /* The WinSock DLL is acceptable. */
#endif

   /* create the socket table - add one for the listening socket */
   socketTable = (SOCKET *) calloc(maxClients+1, sizeof(SOCKET));
   /* if this fails, there's a real problem */
   if (socketTable == NULL)
   {
      fprintf(stderr, "ERR: Couldn't alloc memory for socket table.\n");
      return;
   }

   /* init the table to flag empty slots */
   for (slot=0; slot<=maxClients; slot++)
   {
      socketTable[slot] = -1;
   }

   /* allocate a buffer for our network data (plus 1 byte for safety) */
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
   /* if we had a listening socket running, clean it up */
   if (socketTable[0] != -1)
   {
      /* shut down now. I mean it. right now. */
      shutdown(listenSocket, 2);
      /* how do I close the?  let me count the ways... */
#ifdef WIN32
      closesocket(listenSocket);
      WSACleanup( );
#else
      close(listenSocket);
#endif
   }
   
   /* nuke the socket table */
   if (socketTable != NULL)
      free(socketTable);

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
   u_int afd = fd;
#else
   int afd = fd;
#endif

   switch(set)
   {
      case FD_IS_WRITEABLE:
                           FD_SET(afd, &master_wfdset);
                           break;
      case FD_IS_READABLE:
                           FD_SET(afd, &master_rfdset);
                           break;
      case FD_IS_EXCEPTION:
                           FD_SET(afd, &master_efdset);
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
   u_int dfd = fd;
#else
   int dfd = fd;
#endif

   switch(set)
   {
      case FD_IS_WRITEABLE:
                           FD_CLR(dfd, &master_wfdset);
                           break;
      case FD_IS_READABLE:
                           FD_CLR(dfd, &master_rfdset);
                           break;
      case FD_IS_EXCEPTION:
                           FD_CLR(dfd, &master_efdset);
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
   u_int cfd = fd;
#else
   int cfd = fd;
#endif

   switch(set)
   {
      case FD_IS_WRITEABLE:
                           return (FD_ISSET(cfd, &working_wfdset));
      case FD_IS_READABLE:
                           return (FD_ISSET(cfd, &working_rfdset));
      case FD_IS_EXCEPTION:
                           return (FD_ISSET(cfd, &working_efdset));
   }
   return 0;
}

/* ---------------------------------------------------------------------------------- */
/* client and network functions                                                       */
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
#else
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
 * set_socket_modes()
 * 
 * s           The socket to set
 * 
 * returns:    GOOD_RET if the mode set succeeded (always, actually)
 *
 * Sets some socket modes.
 ------------------------------------------------------------------------------------ */
int
set_socket_modes(SOCKET s)
{
struct linger        sLinger;
int                  iArg;
char                 options[5];

   /* set receive buffer size */
   iArg = rcvBufSize;
   setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *) &iArg, sizeof(int));

   /* set send buffer size */
   iArg = sndBufSize;
   setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *) &iArg, sizeof(int));

   /* turn linger on for 1 second */
   sLinger.l_onoff = 1;
   sLinger.l_linger = 1;
   setsockopt(s, SOL_SOCKET, SO_LINGER, (char *) &sLinger, sizeof(sLinger));

   /* turn keep-alive on */
   options[0] = (char) 1;
   setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &options, sizeof(int));

   return(GOOD_RET);
}

/* ------------------------------------------------------------------------------------
 * start_listener()
 * 
 * returns:    the listening socket if all went well
 *             ERROR_RET if there was a fatal error
 *
 * Creates a server socket that will listen for new TCP client connections.  We set a
 * number of the modes, and the network buffers are set to 0 (we don't actually use
 * this one for data, after all).
 ------------------------------------------------------------------------------------ */
int
start_listener(void)
{
struct sockaddr_in   svrsock;
int                  iArg = 0;

   /* clear the file descriptors */
   fd_clear();

   /* create the listening socket */
   listenSocket = socket(PF_INET, SOCK_STREAM, 0);
   /* was there an error? */
   if (listenSocket < 0)
   {
      return(ERROR_RET);
   }

   /* set up the listener address */
   svrsock.sin_family = PF_INET;
   svrsock.sin_port = htons(port);
   svrsock.sin_addr.s_addr = INADDR_ANY;

   /* bind the socket to our selected port */
#ifdef WIN32
   if (bind(listenSocket, (struct sockaddr *) &svrsock, sizeof(svrsock)) == SOCKET_ERROR)
#else
   if (bind(listenSocket, (struct sockaddr *) &svrsock, sizeof(svrsock)) < 0)
#endif
   {
      fprintf(stderr, "ERR: Error binding listen socket.\n");
      /* clean up the socket */
      nuke_socket(listenSocket);
      return(ERROR_RET);
   }

   /* set receive buffer size */
   iArg = rcvBufSize;
   setsockopt(listenSocket, SOL_SOCKET, SO_RCVBUF, (char *) &iArg, sizeof(int));
   /* set send buffer size */
   iArg = sndBufSize;
   setsockopt(listenSocket, SOL_SOCKET, SO_SNDBUF, (char *) &iArg, sizeof(int));

   /* set the socket to non-blocking, no-delay mode */
   if (set_nonblocking_mode(listenSocket) == ERROR_RET)
   {
      fprintf(stderr, "ERR: Error setting listen socket flags O_NDELAY,O_NONBLOCK.\n");
      /* clean up the socket */
      nuke_socket(listenSocket);
      return(ERROR_RET);
   }

   /* now start it listening */
   if (listen(listenSocket, LISTENBACKLOG) < 0)
   {
      fprintf(stderr, "ERR: Error starting listener.\n");
      /* clean up the socket */
      nuke_socket(listenSocket);
      return(ERROR_RET);
   }

   /* put the listener in our socket table for polling */
   socketTable[0] = listenSocket;

   /* add it to the fdset */
   fd_add(listenSocket, FD_IS_READABLE);

   if (verboseFlag)
      printf("Listen socket started.\n");

   return listenSocket;   
}

/* ------------------------------------------------------------------------------------
 * check_listener()
 * 
 * returns:    the new client socket if there is one
 *             NH_BAD_SOCKET if there was a fatal error
 *
 * Checks the listener socket for new clients
 ------------------------------------------------------------------------------------ */
SOCKET
check_listener(void)
{
SOCKET               newSocket;
struct sockaddr_in   remAddr;
#ifdef WIN32
int         raSize = sizeof(struct sockaddr);
#else
socklen_t   raSize = sizeof(struct sockaddr);
#endif

   /* check to see if we have a pending connect */
   if (fd_check(listenSocket, FD_IS_READABLE))
   {
      /* accept the new client socket */
      newSocket = accept(listenSocket, (struct sockaddr *)&remAddr, &raSize);
      if (newSocket != NH_BAD_SOCKET)
      {
         return(newSocket);
      }
   }

   /* return invalid on either error or no new clients */
   return(NH_BAD_SOCKET);
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
char  buf;

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
 * add_client()
 * 
 * s           The client socket to add to the socket table
 * 
 * returns:    The socket table slot we put the client in
 *             ERROR_RET if there was a fatal error (such as a full table)
 *
 * Add a new client to the table if there's room.
 ------------------------------------------------------------------------------------ */
int
add_client(SOCKET s)
{
int      slot;

   /* if we have room in the client table */
   if (clientCount < maxClients)
   {
      /* walk through it */
      for (slot=1; slot<maxClients; slot++)
      {
         /* look for an empty client slot */
         if (socketTable[slot] == -1)
         {
            /* save our socket in it */
            socketTable[slot] = s;

            /* set the socket to non-blocking, no-delay mode */
            if (set_nonblocking_mode(s) == ERROR_RET)
            {
               fprintf(stderr, "ERR: Error getting client socket flags\n");
               /* clean up the network stuff */
               nuke_socket(s);
               return(ERROR_RET);
            }

            /* set various modes */
            set_socket_modes(s);

            /* add it to the fdsets for polling */
            fd_add(s, FD_IS_READABLE);
            fd_add(s, FD_IS_EXCEPTION);

            /* add to the running client count */
            clientCount++;

            /* save our top client slot */
            if (slot > topClient)
               topClient = slot;

            if (verboseFlag)
               printf("Client added - count=%d.\n", clientCount);

            /* return the slot we put it in */
            return(slot);
         }
      }
   }
   else  /* we have to nuke it due to lack of table space */
   {
      if (verboseFlag)
         printf("Maximum client count reached - new client deleted.\n");
      nuke_socket(s);
   }

   return(ERROR_RET);
}

/* ------------------------------------------------------------------------------------
 * del_client()
 * 
 * s           The client socket to delete from the socket table
 * 
 * returns:    The socket table slot we deleted the client from
 *             ERROR_RET if there was a fatal error (such as a non-existent client)
 *
 * Deletes a client from the socket table, and closes the connection.
 ------------------------------------------------------------------------------------ */
int
del_client(SOCKET s)
{
int   slot;

   /* if we have some clients, */
   if (clientCount > 0)
   {
      /* walk through the socket table */
      for (slot=1; slot<=maxClients; slot++)
      {
         /* look for the matching client slot */
         if (socketTable[slot] == s)
         {
            /* remove this socket from the sets */
            fd_del(s, FD_IS_READABLE);
            fd_del(s, FD_IS_EXCEPTION);
            /* take it out of the table */
            socketTable[slot] = -1;
            /* now go close the actual socket */
            nuke_socket(s);
            /* subtract from the running client count */
            if (clientCount > 0)
               clientCount--;

            if (verboseFlag)
               printf("Client deleted - count=%d.\n", clientCount);

            return(slot);
         }
      }
   }
   return(ERROR_RET);
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
   /* try to read an entire buffer full */
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
void
send_msg(SOCKET source, int msgLen)
{
int      slot;
int      numWrote = 0;
SOCKET   targetSocket;

   /* let's do some simple checks first */
   if ((msgLen < 1) || (clientCount < 2))
      return;
      
   /* walk backwards through the list of clients - this helps prevent
      starvation if low-numbers clients are very active */
   for (slot=topClient; slot>0; slot--)
   {
      /* get the socket for the client */
      targetSocket = socketTable[slot];
      /* if it's live, and not the source of the message */
      if ((targetSocket != -1) && (targetSocket != source) )
      {
         /* try to write to it */
         numWrote = send(targetSocket, bufP, msgLen, 0);
         /* errors mean the death of the client */
         if (numWrote < 0)
            del_client(slot);
      }
   }
}

/* ------------------------------------------------------------------------------------
 * poll_network()
 * 
 * timeout     The polling timeout in millisecs.
 * 
 * returns:    NEUTRAL_RET
 *
 * Polls the client for data (or exceptions), and the listener for new connections.
 ------------------------------------------------------------------------------------ */
int
poll_network(long timeout)
{
int      pollRv = NEUTRAL_RET;
int      rv = NEUTRAL_RET;
SOCKET   newSock;
SOCKET   fdnum;
int      slot;
int      bytesWaiting;
int      bytesRead;

   /* go call select */
   pollRv = fd_select(timeout);
   /* if the return was 0, nothing happened and we timed out */
   if (pollRv == 0)
      return(NEUTRAL_RET);
   else
   /* if we have data waiting... */
   if (pollRv > 0)
   {
      /* walk the client table */
      for (slot=0; slot<=maxClients; slot++)
      {
         /* get the socket from the table */
         fdnum = socketTable[slot];
         /* see if it's a live one */
         if (fdnum != -1)
         {
            /* handle the listener specially (for new clients) */
            if (fdnum == listenSocket)
            {
               newSock = check_listener();
               /* we got something - try to add it */
               if (newSock != NH_BAD_SOCKET)
                  add_client(newSock);
            }
            else
            {
               /* check the socket for a readable condition */
               rv = check_client(fdnum);
               /* okay, we got it */
               if (rv == GOOD_RET)
               {
                  /* check the contents of the socket */
                  bytesWaiting = bytes_avail(fdnum);
                  /* try and read some data */
                  bytesRead = recv_msg(fdnum);
                  /* this is a bit of a hack to more reliably detect a dead
                     client without having to write to it */
                  if ((bytesRead == 0) && (bytesWaiting == 0))
                  {
                     del_client(fdnum);
                     break;
                  }

                  /* if no errors, and we read something */
                  if (bytesRead > 0)
                  {
                     /* send it to all the others */
                     send_msg(fdnum, bytesRead);
                  }
               }
               else
               {
                  if (rv == ERROR_RET)
                  {
                     del_client(fdnum);
                     break;
                  }
               }
            }
         }
      } /* for (slot=0; slot<maxClients; slot++) */
   } /* if (pollRv > 0) */
   else
   {
      if (verboseFlag)
         printf("select returned error %d\n", errno);
   }

   return(pollRv);
}

/* ================================================================================== */

/* ---------------------------------------------------------------------------------- */
/* server functions                                                                   */
/* ---------------------------------------------------------------------------------- */

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
   printf("       -v          verbose mode\n");
   printf("       -b <bytes>  buffer size in bytes (default=%d)\n", BUFFERSIZE);
   printf("       -c <count>  max. number of client connections (default=%d)\n", CLIENTMAX);
   printf("       -p <port>   port to listen on (*REQUIRED*)\n");
   printf("       -r <bytes>  socket recv buffer in bytes (default=%d)\n", TCPBUFSIZE);
   printf("       -t <bytes>  socket transmit buffer in bytes (default=%d)\n", TCPBUFSIZE);
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
}

/* ------------------------------------------------------------------------------------
 * main()
 * 
 ------------------------------------------------------------------------------------ */
int
main(int argc, char *argv[])
{
int   c;

   /* parse the command arguments */
   opterr = 0;
   while ((c = getopt(argc, argv, "hvb:c:p:r:t:")) != -1)
   {
      switch (c)
      {
         case 'h':
                     useage(argv[0]);
                     exit(1);
                     break;
         case 'v':
                     verboseFlag = 1;
                     break;
         case 'b':
                     bufferSize = atoi(optarg);
                     break;
         case 'c':
                     maxClients = atoi(optarg);
                     break;
         case 'p':
                     port = atoi(optarg);
                     break;
         case 'r':
                     rcvBufSize = atoi(optarg);
                     break;
         case 't':
                     sndBufSize = atoi(optarg);
                     break;
         case '?':
                     fprintf(stderr, "ERR: Unknown option `-%c'.\n", optopt);
                     useage(argv[0]);
                     exit(1);
         default:
                     useage(argv[0]);
                     exit(1);
      }
   }

   /* make sure we were given a valid port */
   if ( port <= 0 )
   {
      fprintf(stderr, "ERR: missing or bad port number: %d\n", port);
      useage(argv[0]);
      exit(1);
   }

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
      if (start_listener() != ERROR_RET)
      {
         /* main loop */
         while (runFlag)
         {
            /* poll and process network traffic until an error*/
            if (poll_network(POLL_TIMEOUT) == ERROR_RET)
            {
               runFlag = 0;
               if (verboseFlag)
                  printf("exiting due to error: %d\n", errno);
            }
         }
      }
   }

   /* cleanup */
   deinit();      
   return(0);
}
