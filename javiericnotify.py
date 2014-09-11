#!/usr/bin/python

import os 
import sys

from pyinotify import Notifier
from pyinotify import ThreadedNotifier
from pyinotify import EventsCodes
from pyinotify import ProcessEvent
from pyinotify import WatchManager
import pyinotify

from optparse import OptionParser

### Shell escape
def shescape(s):
   s = s.replace('(','\(')
   s = s.replace(')','\)')
   s = s.replace(' ','\ ')
   s = s.replace("'","\\'")
   s = s.replace('"','\"')
   s = s.replace('&', '\&')
   s = s.replace('|', '\|')
   s = s.replace('$', '\$')
   return s

### File parser
def readConfFile (filename):
    f = open(filename)
    paths = dict()
    for line in f.readlines():
        if len(line.strip()) > 0 :
            if line.strip()[0] == "[" :
                path = line.strip().replace("]", "").replace("[", "")
                paths[path] = dict()
            elif line.strip()[0] == "#" :
                #got # ignore
                0 == 0
            elif line.strip()[0] == ";" :
                #got ; ignore
                0 == 0
            else:
                watch = line.split("=", 1)
                if watch[0].strip() not in paths[path] :
                    paths[path][watch[0].strip()] = []
                paths[path][watch[0].strip()].append(watch[1].strip())

    return paths

### Event managing class
class EvProc(ProcessEvent):
    def __init__(self):
        self.list_IN_ACCESS = []
        self.list_IN_ATTRIB = []
        self.list_IN_CLOSE_NO_WRITE = []
        self.list_IN_CLOSE_WRITE = []
        self.list_IN_CREATE = []
        self.list_IN_DELETE = []
        self.list_IN_DELETE_SELF = []
        self.list_IN_IGNORED = []
        self.list_IN_MODIFY = []
        self.list_IN_MOVE_SELF = []
        self.list_IN_MOVED_FROM = []
        self.list_IN_MOVED_TO = []
        self.list_IN_OPEN = []
        self.list_IN_Q_OVERFLOW = []
        self.list_IN_UNMOUNT = []
        self.str_dir = ""
        
    def exec_event(self, list, event):
        if(0 < len(list) ) :
            for str in list :
		# pnx @ Aug 10 17:14 2009
		#   path and name may contain characters that triggers syntax errors in user scripts.
		#   adding shescape() to these strings. 
                str = str.replace("$path", shescape(event.path))
                str = str.replace("$name", shescape(event.name))
                str = str.replace("$file", shescape(event.name))
                str = str.replace("$event_name", event.event_name)
                #following are broken because I can't be bothered with converting to string
                #str = str.replace("$mask", str(event.mask))
                #str = str.replace("$cookie", str(event.cookie))
                #str = str.replace("$is_dir", event.is_dir)
                #str = str.replace("$wd", event.wd)#

                os.system(str)

    def process_IN_ACCESS(self, event):
        if(options.verbose) : print self.str_dir + "IN_ACCESS: " #+ self.list_IN_ACCESS
        self.exec_event(self.list_IN_ACCESS, event)
    def process_IN_ATTRIB(self, event):
        if(options.verbose) : print self.str_dir + "IN_ATTRIB: " #+ self.list_IN_ATTRIB
        self.exec_event(self.list_IN_ATTRIB, event)
    def process_IN_CLOSE_NOWRITE(self, event):
        if(options.verbose) : print self.str_dir + "IN_CLOSE_NOWRITE: " #+ self.list_IN_CLOSE_NO_WRITE
        self.exec_event(self.list_IN_CLOSE_NO_WRITE, event)
    def process_IN_CLOSE_WRITE(self, event):
        if(options.verbose) : print self.str_dir + "IN_CLOSE_WRITE: " #+ self.list_IN_CLOSE_WRITE
        self.exec_event(self.list_IN_CLOSE_WRITE, event)
    def process_IN_CREATE(self, event):
        if(options.verbose) : print self.str_dir + "IN_CREATE: " #+ self.list_IN_CREATE
        self.exec_event(self.list_IN_CREATE, event)
    def process_IN_DELETE(self, event):
        if(options.verbose) : print self.str_dir + "IN_DELETE: " #+ self.list_IN_DELETE
        self.exec_event(self.list_IN_DELETE, event)
    def process_IN_DELETE_SELF(self, event):
        if(options.verbose) : print self.str_dir + "IN_DELETE_SELF: " #+ self.list_IN_DELETE_SELF
        self.exec_event(self.list_IN_DELETE_SELF, event)
    def process_IN_IGNORED(self, event):
        if(options.verbose) : print self.str_dir + "IN_IGNORED: " #+ self.list_IN_IGNORED
        self.exec_event(self.list_IN_IGNORED, event)
    def process_IN_MODIFY(self, event):
        if(options.verbose) : print self.str_dir + "IN_MODIFY: " #+ self.list_IN_MODIFY
        self.exec_event(self.list_IN_MODIFY, event)
    def process_IN_MOVE_SELF(self, event):
        if(options.verbose) : print self.str_dir + "IN_MOVE_SELF: " #+ self.list_IN_MOVE_SELF
        self.exec_event(self.list_IN_MOVE_SELF, event)
    def process_IN_MOVED_FROM(self, event):
        if(options.verbose) : print self.str_dir + "IN_MOVED_FROM:" #+ self.list_IN_MOVED_FROM
        self.exec_event(self.list_IN_MOVED_FROM, event)
    def process_IN_MOVED_TO(self, event):
        if(options.verbose) : print self.str_dir + "IN_MOVED_TO: " #+ self.list_IN_MOVED_TO
        self.exec_event(self.list_IN_MOVED_TO, event)
    def process_IN_OPEN(self, event):
        if(options.verbose) : print self.str_dir + "IN_OPEN: " #+ self.list_IN_OPEN
        self.exec_event(self.list_IN_OPEN, event)
    def process_IN_Q_OVERFLOW(self, event):
        if(options.verbose) : print self.str_dir + "IN_Q_OVERFLOW: " #+ self.list_IN_Q_OVERFLOW
        self.exec_event(self.list_IN_Q_OVERFLOW, event)
    def process_IN_UNMOUNT(self, event):
        if(options.verbose) : print self.str_dir + "IN_UNMOUNT: " #+ self.list_IN_UNMOUNT
        self.exec_event(self.list_IN_UNMOUNT, event)
               
### Begin exec

### Get commandline
parser = OptionParser(usage="usage: %prog [options] <incronfile>")
parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=True,
                  help="don't print status messages to stdout")
parser.add_option("-d", "--debug",
                  action="store_true", dest="debug", default=False,
                  help="print debugging messages to stdout")

(options, args) = parser.parse_args()

### Parse config file
print args

if 0 == len( args ) :
    inifile = "incrontab.txt"
else :
    inifile = args[0]

if not os.path.exists(inifile) :
    print "File: '%s' does not exist!" % inifile
    sys.exit()

watches = readConfFile(inifile)

wm = WatchManager()
notifier = Notifier(wm, default_proc_fun=EvProc())
wdds = dict()

if(options.verbose) : 
    print "listing watchdirs"
    print watches.keys()

managers = dict()

for watchdir in watches.keys() :
    managers[watchdir] = EvProc()
    mask = 0
    managers[watchdir].str_dir = watchdir
    print "Adding manager for %s" % watchdir
    for evcode in watches[watchdir].keys() :
        print "Adding events for %s" % evcode
	exec("mask |= pyinotify." + evcode)

        for s in watches[watchdir][evcode] :
            cmd = "managers[watchdir].list_" + evcode + ".append(\"" + s.replace("\"", "\\\"") + "\")"
            if(options.debug) : print cmd
            exec( cmd )
        
            if(options.debug) : print "wdds[watchdir] = wm.add_watch("+watchdir+", "+str(mask)+", proc_fun=managers[-1], rec=True ) "
            wdds[watchdir] = wm.add_watch(watchdir, mask, managers[watchdir], True ) 
        if(options.verbose) : print "Watching %s" % watchdir

while True:  # loop forever
    try:
        # process the queue of events as explained above
        notifier.process_events()
        if notifier.check_events():
            # read notified events and enqeue them
            notifier.read_events()
        # you can do some tasks here...
    except KeyboardInterrupt:
        # destroy the inotify's instance on this interrupt (stop monitoring)
        notifier.stop()
        break
