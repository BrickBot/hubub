#!/bin/sh
#\
exec wish "$0" "$@"

#================================================================
# hubchat.tcl
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
   fconfigure $inSource -buffering line -blocking 0
   fileevent $inSource readable [list dataHandler $inSource ]
}

#----------------------------------------------------------------
# This is the incoming data handler.  When we get a line of
# data in the buffer, we then add it to the message box
#----------------------------------------------------------------
proc dataHandler { inSource } {
   .outputBox insert end [gets $inSource]
   .outputBox insert end " \n"
   .outputBox yview [lindex [split [.outputBox index "end - 1 char"] .] 0]
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
  puts [concat "useage: " $argv0 " address port handle"]
  exit 1
}

# parse command line looking for server specs and user handle
set servName [lindex $argv 0]
set servPort [lindex $argv 1]
set myNick [lindex $argv 2]

# set the running flag - we loop until this variable changes
set runFlag 1

# open a connection to each of the servers we are hooking together
set sock [openSocket $servName $servPort]

# Now that we have the socket, configure it
configureSource $sock 

# create the UI
toplevel .t
# make a nice title bar with our handle in it
wm title . [concat $argv0 "- hubub chat client -" $myNick ]
frame .t.f
pack .t.f

text .outputBox -height 10 -width 60 \
   -background white -wrap word \
   -yscrollcommand {.vs set}

scrollbar .vs -orient vertical -command {.outputBox yview}

# position the message output box and it's slider
grid .outputBox -row 0 -column 0
grid .vs -sticky ns -row 0 -column 1

# now the text entry box under it
entry .inputBox -width 60
grid .inputBox -row 1 -column 0

# [Return] sends chat text to the hub and our text box
bind .inputBox <KeyPress-Return> {
   # insert the text iteslf at the end of the box
   .outputBox insert end [.inputBox get ]
   # move to the next line
   .outputBox insert end " \n"
   # adjust the scroll position to keep it visible
   .outputBox yview [lindex [split [.outputBox index "end - 1 char"] .] 0]
   # finally, send it out to the others
   puts $sock [ concat $myNick ">" [.inputBox get ]]
   flush $sock
   # and clean up the input area
   .inputBox delete 0 end
}

# remove all key bindings from the text output box
set btags [bindtags .outputBox]
set i [lsearch $btags Text]
if {$i >= 0 } {
   set btags [lreplace $btags $i $i]
}
bindtags .outputBox $btags
# don't do anything if they hit a key in there
bind .outputBox <KeyPress> {
}

# setup to close cleanly when the window gets closed 
bind .t.f <Destroy> "incr runFlag"

# Announce our presence...
puts $sock [ concat $myNick ": has entered" ]

# and run until we are told to quit
catch {vwait runFlag}

# say our goodbyes
puts $sock [ concat $myNick ": has left" ]

# now cleanup
close $sock

