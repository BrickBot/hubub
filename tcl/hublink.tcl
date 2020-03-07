#!/bin/sh
#\
exec tclsh "$0" "$@"

#================================================================
# hublink.tcl
#
# This little tcl script hooks 2 hubub hubs together, passing
# lines of text from one to another.  Any complete line that
# comes from one is sent to the other.
#
# We use line mode because it's a convenient way for tcl scripts
# to talk to each other.  The hub doesn't care about line 
# conventions.
# 
# Copyright 2000 by Mark Anacker
# Redistribution is allowed under terms of the Artistic License
#================================================================

#----------------------------------------------------------------
# Open the TCP connection to the specified host and port.
#----------------------------------------------------------------
proc openSocket { Host Port } {
   set sock [socket $Host $Port]
   return $sock
}

#----------------------------------------------------------------
# Here's where we set the input socket for line buffered mode,
# and hook the data handler callback into the socket
#----------------------------------------------------------------
proc configureServer { inSock outSock } {
   fconfigure $inSock -buffering line -blocking 0
   fileevent $inSock readable [list dataHandler $inSock $outSock]
}

#----------------------------------------------------------------
# This is the incoming data handler.  When we get a line of
# data in the buffer, we then shove it out to the other socket
#----------------------------------------------------------------
proc dataHandler { inSock outSock } {
   set mesg [gets $inSock]
   puts $outSock $mesg
}

#----------------------------------------------------------------
# This handles fatal errors - we spit out a message to the
# console, and signal the main loop to terminate nicely
#----------------------------------------------------------------
proc bgerror { error } {
   puts [concat "hublink:" $error ]
   set runFlag 0
}

#----------------------------------------------------------------
# Main section
#----------------------------------------------------------------

# check to make sure we have enough arguments
if {$argc != 4} {
  puts "useage: hublink.tcl address1 port1 address2 port2"
  exit 1
}

# parse command line looking for server specs
set servName1 [lindex $argv 0]
set servPort1 [lindex $argv 1]
set servName2 [lindex $argv 2]
set servPort2 [lindex $argv 3]

# set the running flag - we loop until this variable changes
set runFlag 1

# open a connection to each of the servers we are hooking together
set sock1 [openSocket $servName1 $servPort1]
set sock2 [openSocket $servName2 $servPort2]

# Now that we have the sockets, configure them
configureServer $sock1 $sock2
configureServer $sock2 $sock1

# and run until we are told to quit
catch {vwait runFlag}

# now cleanup
close $sock1
close $sock2

