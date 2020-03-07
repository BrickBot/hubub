#!/bin/sh
#\
exec wish "$0" "$@"

#================================================================
# hubwatch.tcl
#
# This script implements a simple GUI chat program, talking to
# other clients via a "hubub" network hub.  It's a very simple
# example of the kind of thing you can do with the hub
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
proc configureSource { inSource } {
   fconfigure $inSource -buffering line -blocking 1
   fileevent $inSource readable [list dataHandler $inSource ]
}

#----------------------------------------------------------------
# This is the incoming data handler.  When we get a line of
# data in the buffer, we then add it to the message box
#----------------------------------------------------------------
proc dataHandler { inSource } {
   set mesg [gets $inSource]
   if {[string length $mesg] > 0} {
      .t.outputBox insert end $mesg
      .t.outputBox insert end " \n"
      .t.outputBox yview [lindex [split [.t.outputBox index "end - 1 char"] .] 0]
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
if {$argc != 2} {
  puts [concat "useage: " $argv0 " address port"]
  exit 1
}

# parse command line looking for server specs and user
set servName [lindex $argv 0]
set servPort [lindex $argv 1]

# set the running flag - we loop until this variable changes
set runFlag 1

# open a connection to each of the servers we are hooking together
set sock [openSocket $servName $servPort]

# Now that we have the socket, configure it
configureSource $sock 

# create the UI
#toplevel .t
# make a nice title bar with our handle in it
#wm title .t [concat $argv0 "- hubub watch client" ]
frame .t
#pack .t.f
grid .t -in . -row 0 -column 0

text .t.outputBox -height 10 -width 60 \
   -background white -wrap word \
   -yscrollcommand {.t.vs set}

scrollbar .t.vs -orient vertical -command {.t.outputBox yview}

#pack .t.f.outputBox

# position the message output box and it's slider
grid .t.outputBox -in .t -row 1 -column 0
grid .t.vs -in .t -sticky ns -row 1 -column 1


# remove all key bindings from the text output box
set btags [bindtags .t.outputBox]
set i [lsearch $btags Text]
if {$i >= 0 } {
   set btags [lreplace $btags $i $i]
}
bindtags .t.outputBox $btags
# don't do anything if they hit a key in there
bind .t.outputBox <KeyPress> {
}

# setup to close cleanly when the window gets closed 
bind .t <Destroy> "incr runFlag"

# and run until we are told to quit
catch {vwait runFlag}

# now cleanup
close $sock

