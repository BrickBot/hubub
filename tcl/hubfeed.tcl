#!/bin/sh
#\
exec tclsh "$0" "$@"

#================================================================
# hubfeed.tcl
#
# This little tcl script connects to a hub, and feeds data either
# to or from it.  If the first command-line argument is "i", we
# are in input mode, and read lines from standard input.  These
# are then sent to the hub (and thus other clients).  Any other
# character there sets us to "output" mode, where lines from the
# hub are sent to standard output.
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
# Here's where we set the input source for line buffered mode,
# and hook the data handler callback into the source
#----------------------------------------------------------------
proc configureSource { inSource outSink } {
   fconfigure $inSource -buffering line -blocking 0
   fileevent $inSource readable [list dataHandler $inSource $outSink]
}

#----------------------------------------------------------------
# This is the incoming data handler.  When we get a line of
# data in the buffer, we then shove it out to the sink
#----------------------------------------------------------------
proc dataHandler { inSource outSink } {
   set mesg [gets $inSource]
   if {[string length $mesg]  > 0} {
      puts $outSink $mesg
      flush $outSink
   }
}

#----------------------------------------------------------------
# This handles fatal errors - we spit out a message to the
# console, and signal the main loop to terminate nicely
#----------------------------------------------------------------
proc bgerror { error } {
   puts [concat $argv0 ": " $error ]
   set runFlag 0
}

#----------------------------------------------------------------
# Main section
#----------------------------------------------------------------

# check to make sure we have enough arguments
if {$argc != 3} {
  puts [concat "useage: " $argv0 " direction address port"]
  puts [concat "(direction may be \"i\" or \"o\")"]
  exit 1
}

# parse command line looking for server specs
set direction [lindex $argv 0]
set servName [lindex $argv 1]
set servPort [lindex $argv 2]

# set the running flag - we loop until this variable changes
set runFlag 1

# open a connection to each of the servers we are hooking together
set sock [openSocket $servName $servPort]

# Now that we have the socket, configure it

# if they selected input mode, set stdin as the source
if { $direction == "i" } {
   configureSource stdin $sock 
} else {
# otherwise use the socket as the input source
   configureSource $sock stdin
}

# and run until we are told to quit
catch {vwait runFlag}

# now cleanup
close $sock

