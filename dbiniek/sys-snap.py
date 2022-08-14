#!/usr/bin/env python
# sys-snap.py - Sys-snap rewritten in python
#
# TODO: fix before reboot, adjust formatting, add formatting options for reports, today/yesterday


# the only config var you'd really ever need to change for now
CFG_LOG_DIRECTORY = '/home/SYS-SNAP' # logging folder, also for pid/error logs, no trailing slash
CFG_LOG_RETENTION = 5  # days to save logs for, logs can be big, wise to watch out with this.
CFG_SKIP_UNIX_SOCKETS = 1 # do we put unix sockets in the logs, or just tcp/udp


def new_func():
    SS_VERSION = '1.0.2'
    return SS_VERSION

SS_VERSION = new_func()

import sys, time, os, getopt
import threading, subprocess
import socket
from struct import pack
from collections import deque
from datetime import datetime
import ConfigParser
import signal
import gzip


try:
    import MySQLdb as _mysql
except ImportError:
    USE_MYSQLDB = False
else:
    import subprocess # THIS MIGHT GET MOVED TO STANDARD IF SOMETHING ELSE NEEDS, for now just mysql
    USE_MYSQLDB = True

WRITE_PICKLE = True
try:
    import cPickle as _json
    PickleError = _json.PickleError
except ImportError:
    WRITE_PICKLE = False
    PickleError = IOError # I know it's ghetto, but just in case someone tries not using cPickle
    try:
        import cjson as _json
    except ImportError:
        try:
            import ujson as _json
        except ImportError:
            print ("ERROR:  Either the json library (python 2.5+) or cjson/ujson is required.\n Please install ujson via easy_install or pip.\n")
            exit()

# some config stuff that isn't config fileized yet
COMPRESS_STUFF = 0
CFG_LOG_INTERVAL = 60
# maximum amount of logs queued at a given time before the writer starts spitting out errors to prevent memory issues
WRITER_QUEUE_MAX = 30

# import stuff that isn't needed for the daemon but is for other stuff here
if (len(sys.argv) > 1 and sys.argv[1] not in ['--start','--daemon']):
    import glob
    
# cpanel/plask/etc check
if os.path.exists('/usr/local/cpanel'):
    CONTROL_PANEL = 'cpanel'
elif os.path.exists('/usr/local/psa'):
    CONTROL_PANEL = 'plesk'
else:
    CONTROL_PANEL = None

if os.path.exists('/proc/user_beancounters'):
    CFG_UBC = 1
else:
    CFG_UBC = 0

CFG_MYSQL_MIN_QUERIES = 2 # minimum # of queries to bother logging mysql stuff
CFG_PROC_MIN_LOAD = 0.0 # minimum load to bother recording activity
CFG_PROC_MIN_MEM = 0 # minimum memory usage to log, logging triggered on either this or load
CFG_LOGPICKER_BEHAVIOR = 0 # 0 means pick log closest to date, 1 means pick log closest before date
CFG_EXTENDED_INFO = False # used by some things like ps to show extra data not normally put in the command

CFG_TZ = False # should be left blank, it gets populated as necessary later.

# the larry sector
CLR_BOLD = "\033[1m"
CLR_RSET = "\033[0;0m"
CLR_RSETB = "\033[0;0m" # same as RSET, but RSET gets nuked by nocolor, rsetb doesn't
CLR_LBLUE = "\033[1;34m"
CLR_GREEN = "\033[0;32m"
CLR_RED = "\033[0;31m"
CLR_YELLOW = "\033[1;33m"
# allow NOCOLOR environ var
if os.environ.get('NOCOLOR',False):
    CLR_RED = ""
    CLR_YELLOW = ""
    CLR_BLUE = ""
    CLR_LBLUE = ""
    CLR_GREEN = ""


TCP_STATES = {1: 'ESTABLISHED', 2: 'SYN_SENT', 3: 'SYN_RECV',
                               4: 'FIN_WAIT1', 5: 'FIN_WAIT2', 6: 'TIME_WAIT',
                               7: 'CLOSE', 8: 'CLOSE_WAIT', 9: 'LAST_ACK', 10: 'LISTEN',
                               11: 'CLOSING'}
if not os.environ.get('HOME',False):
    os.environ['HOME'] = '/root' # otherwise it will do dumb things accessing .my.cnf when run as service

class ProcParser:
        def __init__(self):
            try:
                    self.tickrate = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
            except KeyError:
                    self.tickrate = 100
            self.system_starttime = int(time.time() - self.getSystemUptime())
            self.pidCache = {}
            self.cacheTime = 0
            self.clear()
            self.lastTime = 0

        # loads /proc data
        def load(self):
                self.clear()
                self.getSysInfo()
                if CFG_PROC_MIN_LOAD > 0 and float(self.sysinfo['load1']) < CFG_PROC_MIN_LOAD and float(self.sysinfo['load5']) < CFG_PROC_MIN_LOAD:
                    return None
                self.startTime = int(time.time())
                self.readProcessData()
                self.getNetworkingInfo()
                if CFG_UBC:
                    self.getBeanCounters()
                self.endTime = int(time.time())
                self.lastTime = self.startTime


        def skipLogging(self):
            if CFG_PROC_MIN_LOAD <= 0 and CFG_PROC_MIN_MEM <= 0:
                return False
            loadskip = 0
            memskip = 0
            if CFG_PROC_MIN_LOAD > 0 and ( float(self.sysinfo['load1']) < CFG_PROC_MIN_LOAD and float(self.sysinfo['load5']) < CFG_PROC_MIN_LOAD ):
                loadskip = 1
            if CFG_PROC_MIN_MEM > 0:
                memusage = ( int(filedata['sysinfo']['MemTotal'].split()[0]) - int(filedata['sysinfo']['MemFree'].split()[0]) - int(filedata['sysinfo'].get('Buffers','0').split()[0]) - int(filedata['sysinfo']['Cached'].split()[0]) ) / 1024
                if memusage < CFG_PROC_MIN_MEM:
                    memskip = 1
            if (loadskip or CFG_PROC_MIN_LOAD <= 0) and (memskip or CFG_PROC_MIN_MEM <= 0):
                return True
            else:
                return False
            pass
            
        def clear(self):
            self.processes = []
            self.sockets = {}
            self.sysinfo = {}                
            self.ubc = {}
            self.startTime = None
            self.endTime = None

        def jiffiestoseconds(self,jiffies):
            return float(float(jiffies) / self.tickrate)

        def getSystemUptime(self):
            fp = open('/proc/uptime','r')
            up = fp.readline()
            fp.close()
            uptime, sleeptime = up.split(' ')
            return float(uptime)

        def procAddrToIP(self,addr):
            ip, port = addr.split(':')
            port = int(port, 16)
            ip = socket.inet_ntoa(pack('I',int(ip,16)))
            return "%s:%s" % (ip, str(port))

        def procAddrToIPv6(self,addr):
            ip, port = addr.split(':')
            port = int(port, 16)
            if ip[0:24] == '0000000000000000FFFF0000':
                return "::ffff:%s:%s" % ( socket.inet_ntoa(pack('I',int(ip[24:32],16))) , port)
            if ip == '00000000000000000000000000000000':
                return ":::%s" % port
            ret = []
            zeroes = 0
            for q in [ ip[x:x+4] for x in range(0,31,4) ]:
                if q == '0000' and zeroes > -1:
                    zeroes += 1
                else:
                    if zeroes > 1:
                        ret.append('')
                        zeroes = -1
                    elif zeroes == 1:
                        ret.append('0')
                    if q == '0000':
                        ret.append('0')
                    else:
                        ret.append(q.lstrip('0'))
            return "%s:%s" % (':'.join(ret), port)

        def readProcessData(self):
            for pid in os.listdir('/proc/'):
                if (pid.isdigit()):
                        try:
                            pdata = self.readProcess(pid) # this is a tuple (process data dictionary, process file handles, or None if it failed)
                        except IOError:
                            pass # catch pesky no such process errors
                        if pdata != None:    
                                self.processes.append(pdata)
            if self.cacheTime < self.startTime - 480:
                self.pidCache.clear()
                self.cacheTime = self.startTime
 
        def getBeanCounters(self):
            ubc = {}
            try:
                f = open('/proc/user_beancounters','r')
                for l in f.readlines():
                    if l.find('resource') > -1:
                        continue
                    if l.find(':')>-1:
                        l = l.split(':')[1]
                    s = l.split()
                    if len(s) < 3:
                        continue
                    ubc[s[0]] = (s[1:])
                if len(ubc) > 0:
                    self.ubc = ubc
            except IOError:
                print ("Warning: could not open /proc/user_beancounters")

        def readProcess(self,proc):
            procdata = {}
            try:
                fp = open('/proc/%s/stat' % proc)
                statline = fp.readline()
                fp.close()
            except:
                return None
            if len(statline) < 5:
                return None
            procdata['name'] = statline[ statline.find('('):statline.rfind(')') ]
            if procdata['name'].find(' ') > -1:
                statline = statline.replace(procdata['name'],'NAME',1)
            statcut = statline.split(' ')
            procdata['pid'] = proc
            procdata['name'] = statcut[1].strip('()')
            procdata['state'] = statcut[2]
            procdata['parent'] = statcut[3]
            procdata['cputime'] = str(self.jiffiestoseconds(int(statcut[13]) + int(statcut[14])))
            procdata['cpuchildren'] = str(self.jiffiestoseconds(int(statcut[15]) + int(statcut[16])))
            procdata['nice'] = statcut[18]
            procdata['threadcount'] = statcut[19]
            procdata['starttime'] = int(self.system_starttime + self.jiffiestoseconds(statcut[21]))
            
            try:
                fp = open('/proc/' + proc + '/status','r')
            except:
                return None # either this was a bad process or it disappeared before getting here
            ctxt = 0
            for i in fp.readlines():
                try:
                    k, v = i.split(':',1)
                except ValueError:
                    continue
                if k == 'Uid':
                    procdata['uid'] = v.split()[0]
                elif k == 'VmSize' or k == 'VmPeak' or k == 'VmRSS':
                    procdata[k.lower()] = v.split()[0]
                elif k == 'voluntary_ctxt_switches' or k == 'nonvoluntary_ctxt_switches':
                    ctxt = ctxt + int(v.strip())
            
                procdata['ctxt'] = ctxt    
            if fp:
                fp.close()
            if procdata['starttime'] < self.lastTime:
                cExe, cCmd, cCwd, cEnv = self.getCache(proc, procdata['starttime'], 'exe', 'cmd', 'cwd', 'env')
            else:
                cExe, cCmd, cCwd, cEnv = False, False, False, False
            if not cCmd:
                try:
                    fp = open('/proc/%s/cmdline' % proc)
                    procdata['cmdline'] = fp.readline().replace('\0',' ')
                    fp.close()
                except:
                    pass  # the most critical stuff is in the above parts, pass if you can't get more or you'll throw the other data out
                if len(procdata.get('cmdline','')) < 1:
                    procdata['cmdline'] = '[%s]' % procdata['name']
            else:
                    procdata['cmdline'] = cCmd
                    
            if not cExe:
                try:
                    n = os.readlink('/proc/%s/exe' % proc)
                except OSError:
                    procdata['exe'] = None
                    pass
                else:
                    procdata['exe'] = n.split('\0')[0]
            else:
                procdata['exe'] = cExe
            
            if not cCwd:
                try:
                    n = os.readlink('/proc/%s/cwd' % proc)
                except OSError:
                    procdata['cwd'] = None
                else:
                    procdata['cwd'] = n
            else:
                procdata['cwd'] = cCwd
            
            try:
                f = open('/proc/%s/io' % proc)
                for i in f.readlines():
                    k, v = i.split(':', 1)
                    if k in ['read_bytes', 'write_bytes', 'syscr', 'syscw']:
                        procdata[k] = v.strip()
            except (IOError, ValueError):
                pass # either gone, or kernel doesn't support this
            environ = ''
            envkeep = ['CONSOLE','AUTHENTICATED','ADDRESS','DOCUMENT_ROOT','GATEWAY_INTERFACE','HOME','HOSTNAME','PWD','OLDPWD','PORT',
                     'PROXY_HOSTNAME','QUERY_STRING','REDIRECT_STATUS','REMOTE_ADDR','REMOTE_PORT','REQUEST_METHOD','REDIRECT_STATUS',
                     'REQUEST_URI','SCRIPT_FILENAME','SCRIPT_NAME','SHELL','SSH_CLIENT','SSH_TTY','SSH_CONNECTION','RUSER','PATH_INFO']

            procdata['environ'] = {}
            if not cEnv:
                try:
                    fp = open('/proc/%s/environ' % proc)
                    for i in fp.readlines():
                        environ = environ + i
                    fp.close()
                except IOError:
                    pass  # the most critical stuff is in the above parts, pass if you can't get more or you'll throw the other data out
                
                if len(environ) > 0:
                    try:
                        procdata['environ'] =  dict(filter(lambda x: x[0] in envkeep or x[0].startswith('HTTP_') or x[0].startswith('SERVER_'), [ x.split('=',1) for x in environ.split('\0') if len(x) > 2 ]))
                    except ValueError:
                        pass
            else:
                procdata['environ'] = cEnv
                    
            # file descriptors
            procdata['files'] = {}
             # skipping open files for mysql saves space since most unneeded
            try:
                for i in os.listdir('/proc/%s/fd/' % proc):
                    try:
                        link = os.readlink('/proc/%s/fd/%s' % (proc, i) )
                        #mode = oct(os.lstat('/proc/' + proc + '/fd/' + i).st_mode & 511)
                        mode = 0
                    except:
                        pass   # may have disappeared or be a dud file
                    else:
                        if link.startswith('socket:['):
                            link = link[8:-1]
                            procdata['files'][os.path.basename(i)] = link
                        #elif procdata['exe'] not in [ '/usr/sbin/mysqld', '/usr/libexec/mysqld', '/usr/local/apache/bin/httpd', '/etc/httpd/bin/httpd' ]:
                        #    procdata['files'][os.path.basename(i)] = (link, mode)
            except OSError:
                    pass # probably permission denied
            if procdata['starttime'] < self.startTime - 60 and not self.pidCache.get(proc,False): # only cache things that might be persistent
                self.pidCache[proc] = {'exe': procdata['exe'],'cwd':procdata['cwd'],'cmd': procdata['cmdline'],'env': procdata['environ'], 'start': procdata['starttime'] }
            return procdata   
        
        def getCache(self, pid, starttime, *types):
            arr = self.pidCache.get(pid, False)
            if arr:
                if arr['start'] == starttime:
                    return [ arr[x] for x in types ]
                else:
                    del self.pidCache[pid]
            return [ False for x in types ]
        
           
        def getNetworkingInfo(self):
            try:
                fp = open('/proc/net/tcp','r')
                tcplines = fp.readlines()
                fp.close()
                fp = open('/proc/net/udp','r')
                udplines = fp.readlines()
                fp.close()
                if not CFG_SKIP_UNIX_SOCKETS:
                    fp = open('/proc/net/unix','r')
                    unixlines = fp.readlines()
                    fp.close()
            except IOError:
                return None
            tcp6lines = []
            udp6lines = []
            if os.path.exists('/proc/net/tcp6'):
		            tcp6lines = open('/proc/net/tcp6').readlines()
            if os.path.exists('/proc/net/udp6'):
		            udp6lines = open('/proc/net/udp6').readlines()				
            SOX = self.sockets
            for i in tcplines:
                try:
                    fields = i.split()
                    SOX[fields[9]] = ('TCP', self.procAddrToIP(fields[1]), self.procAddrToIP(fields[2]), int(fields[3],16))
                except ValueError:
                    pass
            for i in tcp6lines:
                try:
                    fields = i.split()
                    SOX[fields[9]] = ('TCP', self.procAddrToIPv6(fields[1]), self.procAddrToIPv6(fields[2]), int(fields[3],16))
                except ValueError:
                    pass            
            for i in udplines:
                try:
                    fields = i.split()
                    SOX[fields[9]] = ('UDP', self.procAddrToIP(fields[1]), self.procAddrToIP(fields[2]))
                except ValueError:
                    pass
            for i in udp6lines:
                try:
                    fields = i.split()
                    SOX[fields[9]] = ('UDP', self.procAddrToIPv6(fields[1]), self.procAddrToIPv6(fields[2]))
                except ValueError:
                    pass
            if not CFG_SKIP_UNIX_SOCKETS:
                for i in unixlines:
                    try:
                        fields = i.split()
                        if len(fields) > 7:
                            SOX[fields[6]] = ('UNIX',fields[7], int(fields[1]))
                        else:
                            SOX[fields[6]] = ('UNIX', None, int(fields[1]))
                    except ValueError:
                        pass

        def getSysInfo(self):
            'getSysStats - currently only gets loadavg and mem info, people can use sar for other stuff, may change in future'
            f = open('/proc/loadavg','r')
            l = f.readline().split()
            f.close()
            self.sysinfo = {'Buffers': '0', 'Cached': '0', 'SwapTotal': '0', 'SwapFree': '0'}
            self.sysinfo['load1'], self.sysinfo['load5'], self.sysinfo['load15'] = l[0], l[1], l[2]
            f = open('/proc/meminfo','r')
            flist = ['MemTotal', 'MemFree', 'Buffers', 'Cached', 'SwapTotal', 'SwapFree']
            for line in f.readlines():
                k, v = line.split(':')
                if k in flist:
                    self.sysinfo[k] = v.strip()
                
        def encapsulate(self):
            if len(self.processes) == 0:
                return None
            if len(self.ubc) > 0:
                return {'START':self.startTime, 'END': self.endTime, 'sysinfo': self.sysinfo, 'processes': self.processes, 'network': self.sockets, 'beancounters': self.ubc}
            else:
                return {'START':self.startTime, 'END': self.endTime, 'sysinfo': self.sysinfo, 'processes': self.processes, 'network': self.sockets}


class SnapWorker(threading.Thread):
    'type in proc mysql apache for now, writer = ref to the writer object to dump data to, miner = object the thread loads and pulls encapsulated data from'
    def __init__(self, name, writer, miner, timer, parentMiner=None):
        threading.Thread.__init__(self)
        self.name = name
        self.type = type
        self.writer = writer
        self.miner = miner
        # self.errorstate = 0 # not yet, but will probably be needed later
        self.timer = timer
        self.error = 0   # used to bail from main loop
        if parentMiner:
            self.daemon = True
        self.keepGoing = True
        self.parentMiner = parentMiner
    
    def run(self):
        while self.keepGoing == True:
            self.miner.load()
            data = self.miner.encapsulate()
            s = 0
            if data != None:
                self.writer.enqueue(self.name, data)
                if self.parentMiner != None:
                    pst = self.parentMiner.startTime
                    if not pst:
                        s = self.timer
                    else:
                        s = (self.timer - self.miner.endTime + self.parentMiner.startTime) % self.timer # sync with parent, but make up for weird glibc timer bugs
                if not s:
                    s = self.timer - (self.miner.endTime - self.miner.startTime)  # try to sync timing, but if it's too big a lag just go normal to avoid overload
            if s < self.timer / 2:
                s = self.timer
            time.sleep(s)   



class MySQLWatcher:
    def __init__(self):
        self.processlist = []
        self.error = None

    def load(self):
        self.startTime = int(time.time())
        self.endTime = 0
        self.processlist = []
        self.error = None
        if USE_MYSQLDB:
            try:
                if CONTROL_PANEL == 'plesk':
                    fz=open('/etc/psa/.psa.shadow','r')
                    fzpw = fz.readline().strip()
                    fz.close()
                    db = _mysql.connect('localhost', 'admin', fzpw)
                else:
                    db = _mysql.connect(read_default_file='/root/.my.cnf',connect_timeout=5) # 5 sec timeout, really there's something wrong if it takes longer
                dc = db.cursor()
                dc.execute("SHOW FULL PROCESSLIST")
                self.processlist.append([ k[0] for k in dc.description ])           
                for row in dc.fetchall():
                    self.processlist.append(row)
                db.close()
            except:
                    self.error = ' '.join([ str(i) for i in sys.exc_info()[1].args])
        else:
            proc = subprocess.Popen(['mysql', '-Be', 'SHOW FULL PROCESSLIST'], stdout=subprocess.PIPE, shell=False)
            headers = proc.stdout.readline()
            if len(headers) == 0:
                return None
            headers = headers.split()
            procs = []
            headers = [ k.lower() for k in headers ]
            self.processlist.append(headers)
            while True:
                line = proc.stdout.readline()
                if line != '':
                    line = line.strip()
                    line = line.split("\t",len(headers))

                    self.processlist.append(line)
                else:
                    break
            proc.stdout.close()
        self.endTime = int(time.time())
            
    def encapsulate(self):
        if len(self.processlist) < CFG_MYSQL_MIN_QUERIES or self.endTime < self.startTime:
            if self.error:
                if not self.endTime or self.endTime < self.startTime:
                    self.endTime = self.startTime
                return {'START': self.startTime, 'END': self.endTime, 'processlist': None, 'error': self.error}
            return None
        return {'START': self.startTime, 'END': self.endTime, 'processlist': self.processlist}




# this is a bare class at the moment, as the script fills out its actual configuration will be added, for now it just dumps json to timestamp.txt in the CFG_LOG_DIRECTORY folder
class SnapWriter:
    def __init__(self, threadlock, dir=None,maxQueue=None):
        if dir == None:
            dir = CFG_LOG_DIRECTORY
        if maxQueue == None:
            self.maxQueue = WRITER_QUEUE_MAX
        else:
            self.maxQueue = maxQueue
        self.lock = threadlock
        self.queue = deque()
        self.workingdir = dir
        self.lastdiskcheck = 0
        self.disklocked = False
        self.subqueuemap = {} # child : parent
        self.subqueuedata = {} # parent : { child1: data,child2: data, etc } 
        if not os.path.exists(dir):
            try:
                os.makedirs(dir, 0755)
            except OSError:
                # we might be out of disk
                sys.stderr.write('ERROR: could not create log directory!')
                sys.exit(1)
        self.readystate = 0 # if anything else, processing queue and can't be called to write until readystate goes back to 0
        self.lastmid = 0 # last midnight used for directory to put files in
        signal.signal(signal.SIGTERM, self.sighandler)


    def setParent(self, child, parent):
        self.subqueuemap[child] = parent

    def getParent(self,child):
        return self.subqueuemap.get(child, None)
        
    def enqueue(self, prefix, data): # pass a dict to be dumped with json, prefix defines the 'label' for the data to be used by writer, saved as tuple
        self.lock.acquire()
        if len(self.queue) > self.maxQueue:
            try:
                sys.stderr.write('Error: queue too big to enqueue new data')
            except (IOError, OSError):
                pass # error in writing error, what else can you do ?!?
            self.lock.release()
            return False

        sqm = self.subqueuemap.get(prefix, False)
        if sqm:
            self.subqueue(prefix, data)
        else:
            self.queue.append((prefix, data))
        self.lock.release()
        
    def dequeue(self):
        self.lock.acquire()
        dtup = self.queue.popleft()
        self.lock.release()
        return dtup

    def subqueue(self, prefix, data):
        pname = self.getParent(prefix)
        if pname:
            if not self.subqueuedata.get(pname, False):
                self.subqueuedata[pname] = { prefix: data }
            else:
                self.subqueuedata[pname][prefix] = data

    def ready(self):
        if len(self.queue) > 0 and self.readystate == 0:
            return True
        else:
            return False
    
    def write(self):
        now = time.time()
        if now - self.lastdiskcheck > 600 or (self.disklocked and now - self.lastdiskcheck > 15):
            dspace = getDiskSpace()
            if dspace < 262144000:
                try:
                    sys.stderr.write('DISK UNDER 250M FREE\n')
                except Exception:  
                    # if you get an error writing the error, well .. chances are the disk is full so just sit still
                    pass
                self.disklocked = True
            elif self.disklocked == True:
                self.disklocked == False
        if self.disklocked:
            return False

        while len(self.queue) > 0:
            self.readystate = 1
            errstate = 0
            prefix, data = self.dequeue()

            if prefix != None and data != None:
                if data['START']:
                    dtime = data['START']
                else:
                    dtime = int(time.time())
                if self.subqueuedata.get(prefix, False):
                    self.lock.acquire()
                    for sqk, sqv in self.subqueuedata[prefix].iteritems():
                        data['C-%s' % sqk] = sqv
                    self.lock.release()
                    del self.subqueuedata[prefix]
                # get it into the right archive folder
                if dtime - self.lastmid > 82600: # possibly a new day, dont forget dst shifts!
                    dmid = midnight()
                    if dmid != self.lastmid:
                        self.lastmid = dmid
                        if not os.path.exists('%s/arch-%s' % (CFG_LOG_DIRECTORY, self.lastmid)):
                            try:
                                os.makedirs('%s/arch-%s' % (CFG_LOG_DIRECTORY, self.lastmid))
                            except (OSError, IOError):
                                errstate = 1

                if errstate > 0:
                    try:
                        sys.stderr.write('ERROR(%s): could not write snapshot log.')
                    except (OSError,IOError):
                        pass # gonna bail anyway, who cares
                    return False

                try:
                    if COMPRESS_STUFF == 1:
                        f = gzip.open('%s/arch-%s/%s-%s.txt.gz' % (self.workingdir, self.lastmid, prefix, dtime), 'w')
                    elif COMPRESS_STUFF == 2:
                        f = bz2.BZ2File('%s/arch-%s/%s-%s.txt.bz2' % (self.workingdir, self.lastmid, prefix, dtime), 'w')
                    else:
                        f = open('%s/arch-%s/%s-%s.txt' % (self.workingdir, self.lastmid, prefix, dtime), 'w')
                    if WRITE_PICKLE:
                        _json.dump(data,f,protocol=-1)
                    else:
                        f.write(_json.dumps(data))
                    f.close()
                except IOError:
                    if sys.exc_info()[1] == 2: # ENOENT
                        os.makedirs('%s/arch-%s' % (CFG_LOG_DIRECTORY))
                        f = open('%s/arch-%s/%s-%s.txt' % (self.workingdir, self.lastmid, prefix, dtime), 'w')
                        f.write(_json.dumps(data))
                        f.close()
        self.readystate = 0
        return True

    def sighandler(self, signal, frame):
        if self.readystate == 0:
            os._exit(0)
        then = time.time()
        while self.readystate != 0 and time.time() - then < 10:
            time.sleep(.1)
        os._exit(0)


def syssnapLoop(interval=60):
    SNAPLOCK = threading.Lock()
    writer = SnapWriter(SNAPLOCK)
    pparser = ProcParser()
    myparser = MySQLWatcher()
    
    # initialize the workers
    wProc = SnapWorker('proc', writer, pparser, interval)
    wProc.start()
    myProc = SnapWorker('mysql', writer, myparser, interval, pparser)
    writer.setParent('mysql','proc')
    myProc.start()
    # let's make sure things actually started...
    time.sleep(1)
    if threading.activeCount() < 3: # !#%@^
        print "At least one thread died on start.  Check /root/SYS-SNAP/syssnap.err."
        f = open('%s/syssnap.pid' % CFG_LOG_DIRECTORY, 'w')
        f.write("%s E" % os.getpid())
        f.close()
        os._exit(1)
    else: # we successfully started
        f = open('%s/syssnap.pid' % CFG_LOG_DIRECTORY, 'w')
        f.write("%s R" % os.getpid())
        f.close()
    # entering main thread loop
    while True:
        if writer.ready():
            writer.write()
        if not wProc.isAlive(): # wake up
            wProc = SnapWorker('proc', writer, pparser, interval)
            wProc.start()

        time.sleep(3)
        
def daemonize(logdir=None):
    if logdir == None:
        logdir = CFG_LOG_DIRECTORY
    if (hasattr(os, "devnull")):
       REDIRECT_TO = os.devnull
    else:
       REDIRECT_TO = "/dev/null"
    try:
        pid = os.fork()
    except OSError, e:
        raise Exception, "%s [%d]" % (e.strerror, e.errno)
    if pid == 0:
        os.setsid()
        try:
            pid2 = os.fork()
        except OSError:
            print "%s [%d]" % (sys.exc_info()[0], sys.exc_info()[1])
        if pid2 == 0:
            os.chdir('/')
            os.umask(0177)
        else:
            os._exit(0)
    else:
        os._exit(0)
    import resource
    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if (maxfd == resource.RLIM_INFINITY):
        maxfd = 1024
    
    for fd in range(0,maxfd):
        try:
            os.close(fd)
        except OSError:
            pass

    os.open(REDIRECT_TO, os.O_RDWR)
    if not os.path.exists(logdir):
        os.makedirs(logdir, 0711)
    os.open('%s/syssnap.err' % logdir, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    os.dup2(1,2)
    sys.stderr.write('%s: sys-snap version %s started.\n' % (str( datetime.fromtimestamp(int(time.time())) ) , SS_VERSION) )
    fp = open(CFG_LOG_DIRECTORY + '/syssnap.pid', 'w')
    fp.write('%s P' % str(os.getpid()))
    fp.close()    

def getDaemonPID(ext = False):
    if os.path.exists(CFG_LOG_DIRECTORY + '/syssnap.pid'):
        fp = open(CFG_LOG_DIRECTORY + '/syssnap.pid','r')
        pid, plabel = fp.readline().strip().split(' ', 1)
        fp.close()
        if os.path.exists('/proc/' + pid + '/cmdline'):
            fp = open('/proc/' + pid + '/cmdline','r')
            if fp.readline().find('sys-snap') > -1:
                if ext:
                    return (pid, plabel)
                else:
                    if plabel != 'E':
                        return int(pid)
                    else:
                        return None
            else:
                if ext:
                    return (None, None)
                else:
                    return None
    if ext:
        return (None, None)
    else:
        return None

def getDateFromArgs(args):
    'reads arguments and parses into a date to show a log from'
    global CFG_LOGPICKER_BEHAVIOR
    day, month, year, hour, minute, seconds = (-1,-1,-1,-1,-1,-1)
    dnow = datetime.now()
    negit = 0
    rangeDetected = False
    rangeInfo = []
    add30 = False
    try:
        for i in args:
            if i.find('/') > 0 and day == -1:
                arr = i.split('/')
                if len(rangeInfo) > 0:
                    print "WARNING: For statistics, date needs to be before time.  Date ignored."
                if len(arr) > 3:
                    raise ValueError('Invalid date')
                elif len(arr) == 3:
                    month = int(arr[0])
                    day = int(arr[1])
                    year = int(arr[2])
                    if year < 100:
                        year += 2000
                else:
                    month = int(arr[0])
                    day = int(arr[1])
                    year = dnow.year
            elif i.find(':') > 0 and hour == -1:
                try:
                    arr = [ int(x) for x in i.split(':') ]
                except ValueError:
                    print "Invalid date.  For single times, use times like '5:00 pm' or '17:00'.  For statistics, you can use hourly intervals (sys-snap 5 shows stats for 5:00-5:59, sys-snap 5-8 shows 5:00-8:00).  See sys-snap -h for more info."
                    sys.exit(1)
                if len(arr) > 3 or arr[0] < 0 or arr[0] > 23 or arr[1] < 0 or arr[1] > 59 or (len(arr) == 3 and (arr[2] < 0 or arr[2] > 59)):
                    raise ValueError('Invalid time')
                hour = arr[0]
                minute = arr[1]
                if len(arr) == 3:
                    seconds = arr[2]
                else:
                    seconds = 0
                    add30 = True
            elif i.lower() == 'pm' and hour < 12:
                if rangeDetected:
                    if hour + (rangeInfo[1] - rangeInfo[0])/3600 <= 12:
                        rangeInfo[0] += 43200
                        rangeInfo[1] += 43200
                hour+=12
            elif i.lower() == 'am' and hour == 12:
                if rangeDetected:
                    rangeInfo[0] -= 43200
                    rangeInfo[1] -= 43200
                else:
                    hour = 0
            elif i == 'current' or i == 'now':
                CFG_LOGPICKER_BEHAVIOR = 1 # prevent it from trying to open a brand new file that's prob not done being written
                return int(time.time())
            elif i == 'before':
                CFG_LOGPICKER_BEHAVIOR = 1
            elif i == 'reboot' or i == 'boot':
                fp = open('/proc/uptime','r')
                up = fp.readline()
                fp.close()
                uptime, sleeptime = up.split(' ')
                # CFG_LOGPICKER_BEHAVIOR = CFG_LOGPICKER_BEHAVIOR | 2 # pending update to make wider time for reboots
                return int(time.time() - float(uptime))
            elif i == 'prev' or i == 'previous':
                pF,tF,nF = readReadCache()
                if pF == 0:
                    print "No previous log available."
                    os._exit(0)
                if pF > 0:
                    return pF
            elif i == 'next':
                pF,tF,nF = readReadCache()
                if nF == 0:
                    print "Next log not available from cache, will search for something newer..."
                    nF = tF * 2 - pF
                    return nF
                if nF > 0:
                    return nF
            elif i == 'last':
                pF,tF,nF = readReadCache()
                if tF == 0:
                    print "No last log data available."
                    os._exit(0)
                if tF > 0:
                    return tF
            elif i.isdigit() and int(i) < 24 and int(i) >= 0 and not rangeDetected:
                # just an hour, for a single hour range
                rangeDetected = True
                hour = int(i)
                if year == -1:
                    year = dnow.year
                if day == -1:
                    day = dnow.day
                    month = dnow.month
                stTime = int( time.mktime(datetime(year,month,day,hour,0,0).timetuple()) )
                rangeInfo = [ stTime, stTime + 3659 ]
            elif i.find('-') > -1:
                if i[0] == '-':
                    print "Invalid argument %s.  If you are trying to use an option, it must be set before time parameters." % i
                    sys.exit(1)
                # range, eg 6-8
                rangeDetected = True
                rstart, rend = [ int(x) for x in i.split('-',1) ]
                if rend < rstart and rend < 12 and rstart <= 12:
                    rend += 12
                if rend == 0 and rstart > 12:
                    rend = 24
                if rstart > 23 or rstart < 0 or rend > 24 or rend < 0 or rend < rstart:
                    print "Invalid time range: %s to %s\n" % (rstart, rend)
                    sys.exit(1)
                hour = rstart
                if year == -1:
                    year = dnow.year
                if day == -1:
                    day = dnow.day
                    month = dnow.month
                if rend < 24:
                    rangeInfo = [ int( time.mktime(datetime(year,month,day,rstart,0,0).timetuple()) ), int(time.mktime(datetime(year,month,day,rend,0,0).timetuple())) + 59 ]
                else:
                    rangeInfo = [ int( time.mktime(datetime(year,month,day,rstart,0,0).timetuple()) ), int(time.mktime(datetime(year,month,day,23,0,0).timetuple())) + 3659 ]
                
        # END parser switching
                    
        if year == -1:
                year = dnow.year
        if minute == -1:
            if day == -1 or month == -1:
                raise ValueError('Time required.')
            hour = 0
            minute = 0
            seconds = 0
            negit = 1
            
        if day == -1:
            if (hour * 60 + minute) < (dnow.hour * 60 + dnow.minute + 60): # add 60m to avoid edge scenarios with a couple min in the future
                day = dnow.day
                month = dnow.month
            else:
                dyest = datetime.fromtimestamp(time.time() - 86400)
                day = dyest.day
                month = dyest.month
                year = dyest.year

        
        target_date = datetime(year,month,day,hour,minute,seconds)
        ret_time = int(time.mktime(target_date.timetuple()))
        if add30 and CFG_LOGPICKER_BEHAVIOR == 0:
            ret_time = '+%s' % ret_time
        elif negit == 1:
            ret_time *= -1
        if rangeDetected:
            return rangeInfo
        return ret_time
    except OSError:
        print "Invalid date/time."
        return None


# refactoring next step
def getNearestLog(timestamp, type = 'proc', maxdistance = 60):
    mid = midnight()
    f = False
    archlist = False
    offset = mid % 86400

    archlist = [ int(x.split('-')[-1]) for x in sorted(glob.glob('%s/arch-*' % CFG_LOG_DIRECTORY)) ]
    tmid = timestamp - (timestamp - offset) % 86400
    try:
        tk = archlist.index(tmid)
    except ValueError: # not in the array!
        tk = None
    if tk != None:
        f = getNearestLogInDir( timestamp, '%s/arch-%s' % (CFG_LOG_DIRECTORY, tmid), maxdistance )
        if isinstance(f, tuple): # was an edge, check somewhere nearby
            if f[2] == 1:
                if tk == len(archlist) - 1:
                    f2 = getNearestLogInDir(timestamp, CFG_LOG_DIRECTORY, maxdistance, norecurse=True)
                else:
                    f2 = getNearestLogInDir(timestamp, '%s/arch-%s' % (CFG_LOG_DIRECTORY, archlist[tk + 1]), maxdistance, norecurse=True)
            else:
                if tk == 0:
                    # done, there shouldnt be anything earlier than this
                    return f[0]
                else:
                    f2 = getNearestLogInDir(timestamp,'%s/arch-%s' % (CFG_LOG_DIRECTORY, archlist[tk - 1]), maxdistance, norecurse=True)
            if f2: # didnt get a false
                if abs(f2[1] - timestamp) < abs(f[1] - timestamp):
                    return f2[0]
                else:
                    return f[0]
            else:
                return f[0]
        else: # it wasn't an edge case or anything, just return the damn file
            if f:
                return f

    # at this point all we have left is a today condition or false, so search the main folder for todays or unarchived logs
    f = getNearestLogInDir(timestamp, CFG_LOG_DIRECTORY, maxdistance)
    if isinstance(f, tuple):
        if not archlist: # this means it never actually went through the list, go and see if this is an edge case for yesterday
            archlist = [ int(x.split('-')[-1]) for x in sorted(glob.glob('%s/arch-*' % CFG_LOG_DIRECTORY)) ]
            f2 = getNearestLogInDir(timestamp, '%s/arch-%s' % (CFG_LOG_DIRECTORY, archlist[-1]), maxdistance, norecurse=True)
            if f2:
                if abs(f2[1] - timestamp) < abs(f[1] - timestamp):
                    return f2[0]
                else:
                    return f[0]
            else:
                return f[0]
        else: # we already went the per-dir route, just return from f
            return f[0]
    return f

def getNearestLogInDir(timestamp, directory, maxdistance = 60, type = 'proc',norecurse = False):
    ''' can return 4 things:  an answer (the filename), False (couldnt find anything), or a tuple.
    The tuple will be (filename, file timestamp, 1 or -1): if the third part is 1, take best between 'today' and 'tomorrow'
    if it's -1, take best between today and yesterday. 
    if it's 0, it means it came off a no recurse and its only using the tuple to decide the winner'''
    files = dict([ (int(x[(x.find(type)+len(type)+1):].split('.')[0]), x) for x in glob.glob('%s/%s-*' % (directory, type)) ])
    fkeys = sorted(files)
    if len(fkeys) == 0:
        return False
    elif len(fkeys) == 1:
        closest = 0
    else:
        closest = int(len(fkeys) * float(timestamp - fkeys[0])  / float(fkeys[-1] - fkeys[0])) # get percentage of way through list that timestamp may exist at to start search
    if closest>=len(files):
        closest = len(files) - 1
    elif closest <= 0:
        closest = 0
    stepping = 1
    if fkeys[closest] == timestamp:
        return files[fkeys[closest]]
    if fkeys[closest] > timestamp:
        stepping = -1
        cap = 0
    else:
        cap = len(fkeys) - 1
    while True:
        if closest == cap:
            if norecurse == True:
                return (files[fkeys[closest]], fkeys[closest], 0) # this will be used to take best of 'original' answer
            if fkeys[closest] < timestamp and CFG_LOGPICKER_BEHAVIOR == 1: # really only happens for last one but might somehow happen on first sometimes
                return files[fkeys[closest]]
            if abs(fkeys[closest] - timestamp) <= maxdistance * 60:
                if cap == 0:
                    answer = -1
                else:
                    answer = 1
                return (files[fkeys[closest]], fkeys[closest], answer) 
            else:
                return False
        if fkeys[closest + stepping] * stepping > timestamp * stepping : # passing target number
            if CFG_LOGPICKER_BEHAVIOR == 1:
                return files[fkeys[min(closest, closest + stepping)]]
            if abs(fkeys[closest + stepping] - timestamp) < abs(fkeys[closest] - timestamp):
                return files[fkeys[closest + stepping]]
            else:
                return files[fkeys[closest]]
        closest = closest + stepping
# end refactoring next step


def writeReadCache(prev,now,next):
    if not isinstance(prev,int):
        next = next.split('-')[-1].split('.')[0]
        now = now.split('-')[-1].split('.')[0]
    if prev == now:
        prev = '0'
    if next == now:
        next = '0'
    f = open(CFG_LOG_DIRECTORY + '/syssnap.cache','w')
    f.write('%s,%s,%s' % (prev, now, next))
    f.close()

def readReadCache():
    f = open(CFG_LOG_DIRECTORY + '/syssnap.cache','r')
    l = f.readline()
    f.close()
    if l:
        l = l.split(',')
        if len(l) == 3:
            l[0] = int(l[0])
            l[1] = int(l[1])
            l[2] = int(l[2])
            return l
    return None

def timeFromLog(logname):
    return int(logname.split('.')[0].split('-')[-1])

def read_json(logfile):
    'deceptive - this really reads pickle or json'
    if logfile.find('/') == -1:
        logfile = '%s/%s' % (CFG_LOG_DIRECTORY, logfile)
    if os.path.exists(logfile):
        if logfile.find('.gz') > -1:
            f = gzip.open(logfile,'r')
            jsdata = ''.join(f.readlines())
            f.close()
        else:
            f = open(logfile, 'r')
            jsdata = ''.join(f.readlines())
            f.close()
        try:
            if len(jsdata) and jsdata[0] == '{' and _realjson != None:
                return _realjson.loads(jsdata)
            else:
                return _json.loads(jsdata)
        except (ValueError, EOFError,PickleError): # catch pickle errors due to badly written files
            sys.stderr.write('Warning: could not process log %s due to malformed pickle data.  If reading stats, try an earlier or later log/time.\n' % logfile)
            return None

def maybe_float(s):
    'converts an str to a float, if its actually a floatable value, otherwise just sends back the str'
    if isinstance(s,int):
        return float(s)
    if s.isdigit() or (s.startswith('-') and s[1:].isdigit()):
        return float(s)
    s2 = s.split('.')
    if len(s2) == 2 and (s2[0].isdigit() or s2[0][1:].isdigit() and s2[0].startswith('-')) and s2[1].isdigit():
        return float(s)
    return s
    
def printProcessData(filedata, *shopts, **opts):
    # header
    totalmem = int(filedata['sysinfo']['MemTotal'].split()[0])
    sortkeys = {'cpu': '__SPECIAL__','cputime': 'cputime', 'mem': 'vmrss', 'vm': 'vmsize', 'state': 'state','nice': 'nice', 'ior': 'read_bytes','iow': 'write_bytes', 'reads': 'syscr', 'writes': 'syscw', 'user':'uid', 'children': 'cpuchildren','ctxt':'ctxt'}
    sortkeykeys = sortkeys.keys()
    sorter = opts.get('sort',False)    
    if sorter and sorter not in sortkeykeys:
        print CLR_RED + "Warning: invalid sort option (check --help for valid choices): " + sorter + CLR_RSET
        sys.exit()

    if opts.get('seconds'):
        secct = 3
    else:
        secct = 0

    if not opts.get('skipheaders',False):
        if isinstance(display_opts.get('logrequest'), int):
            if abs(filedata['START'] - display_opts['logrequest']) > 300:
                cl_start = CLR_RED
                cl_end = CLR_RSET
            elif abs(filedata['START'] - display_opts.get('logrequest') ) > 100:
                cl_start = CLR_YELLOW
                cl_end = CLR_RSET
            else:
                cl_start = ''
                cl_end = ''

        print 'Time:\t%s%s%s' % (cl_start, str(datetime.fromtimestamp(filedata['START'])), cl_end)
        print "Load:\t" + filedata['sysinfo']['load1'] + ', ' + filedata['sysinfo']['load5'] + ', ' + filedata['sysinfo']['load15']
        print "Memory: " + str(totalmem / 1024) + " MB\tFree: " + str(int(filedata['sysinfo']['MemFree'].split()[0]) / 1024) + \
        " MB (" + str((int(filedata['sysinfo']['MemFree'].split()[0]) + int(filedata['sysinfo'].get('Buffers','0').split()[0])  + \
        int(filedata['sysinfo']['Cached'].split()[0]) )/ 1024) + " MB)\tBuffers: " + str(int(filedata['sysinfo'].get('Buffers','0').split()[0]) / 1024) + \
        " MB\tCached: " + str(int(filedata['sysinfo']['Cached'].split()[0]) / 1024) + " MB\tSwapFree: " + str(int(filedata['sysinfo']['SwapFree'].split()[0]) / 1024) + \
        ' MB / ' + str(int(filedata['sysinfo']['SwapTotal'].split()[0]) / 1024) + ' MB'
        
        print ""
        print "USER         PID %%CPU %%MEM    VSZ   PEAK    RSS ST NI    CPU        %sSTART    IOR  IOW CMD" % (' '*secct)

    if sorter == 'cpu':
         filedata['processes'] = sorted(filedata['processes'], key=lambda x: float(x.get('cputime',0)) / ( time.time() - float(x['starttime'])) )
    elif sorter in sortkeykeys:
        filedata['processes'] = sorted(filedata['processes'], key=lambda x: maybe_float(x.get(sortkeys[sorter], '0')))
    else:
        parenttable = parentKeyProcesses(filedata['processes'])
        filedata['processes'] = sorted(filedata['processes'], key=lambda x: parenttable[x['pid']] )
    if opts.get('extended', False):
        envlist = 'RUSER REMOTE_ADDR REQUEST_URI HTTP_HOST SSH_CONNECTION SCRIPT_FILENAME REQUEST_METHOD SERVER_NAME USER IP'.split()

    for p in filedata['processes']:
        if sorter not in sortkeykeys:
            indct = len( parenttable[p['pid']].split('-') ) - 2
            if indct == -1:
                indct = 0
        else:
            indct = 0
        cmdIndent = '   ' * indct
        if opts.get('network',False):
            print CLR_GREEN,
        try:
            usr = getpwuid(int(p['uid']))[0]
            if len(usr) > 8:
                print str(p['uid']).ljust(9),
            else:
                print usr.ljust(9),
            cpuperc = round(float(p.get('cputime',0)) * 100.0 / ( time.time() - float(p['starttime'])), 1)
            if cpuperc >= 100:
                cpuperc = int(round(cpuperc))
            print str(p['pid']).rjust(6) + str( cpuperc ).rjust(5)  +  \
                      str(round(float(p.get('vmrss',0)) * 100 / float(totalmem), 1)).rjust(5) + gigaprint(p.get('vmsize',0), True).rjust(7) + \
                      gigaprint(p.get('vmpeak',0), True).rjust(7)+ gigaprint(p.get('vmrss',0), True).rjust(7) + " " + p['state'].ljust(2) + str(p['nice']).rjust(3),
            print timePrint(float(p['cputime'])).rjust(7), datePrint(int(p['starttime']), secct).rjust(11 + secct),
            if p['pid'] == '1':
                print '    0    0',
            else:
                print gigaprint(int(p.get('read_bytes',0))).rjust(5) + gigaprint(int(p.get('write_bytes',0))).rjust(5),
            print cmdIndent + str(p['cmdline']).strip(),
        except KeyError:
            pass # this is a temporary try block because of missing stuff in older logs
        if opts.get('network',False):
            print CLR_RSET,
        print "" # end the line

        if opts.get('extended', False):
            if opts.get('extclean', False) and p.get('environ',[]).get('REQUEST_URI', False):
                # make nice with the php kiddies
                if opts.get('SERVER_PORT', 80) == 443:
                    proto = 'https'
                else:
                    proto = 'http'
                httpref = ''
                if opts.get('HTTP_REFERER',False):
                    httpref = ' %s' % opts['HTTP_REFERER']
                requri = p['environ']['REQUEST_URI']
                if requri.find('?') == -1 and len(p['environ'].get('QUERY_STRING','')) > 0:
                    requri += p['environ']['QUERY_STRING']
                dlp = '%s %s://%s%s %s %s%s' % ( p['environ'].get('REQUEST_METHOD','???'), proto, p['environ'].get('HTTP_HOST','???'), requri, p['environ'].get('HTTP_USER_AGENT','[unknown user agent]'), p['environ'].get('REMOTE_ADDR','[unknown ip]'), httpref) 
            else:
                dlist = []
                if p.get('environ', False):
                    for i in sorted(p['environ']):
                        dlist.append('%s=%s' % (i,p['environ'][i]))
                n = p['files'].get('0', None)
                if n and (n[0].find('/dev/pt') > -1 or n[0].find('/dev/tt') > -1):
                    dlist.append('TTY=' + n[0].replace('/dev/',''))
                if p.get('cwd',None):
                    dlist.append('CWD=' + p['cwd'])
                if p.get('cpuchildren',None) and float(p['cpuchildren']) > 0:
                    dlist.append('CPU_CHILDREN=' + p['cpuchildren'])
                if p.get('ctxt',0) > 3:
                    dlist.append('CTXT=%s' % p['ctxt'])
                if int(p.get('threadcount',0)) > 3:
                    dlist.append('THREADS=' + p['threadcount'])
                if int(p.get('syscr',0)) > 24:
                    dlist.append('SYS_READS=' + p['syscr'])
                if int(p.get('syscw',0)) > 24:
                    dlist.append('SYS_WRITES=' + p['syscw'])
                dlist = sorted(dlist)
                dlp = ' '.join(dlist)
            if len(dlp) > 0:
                print CLR_LBLUE + '\t' + dlp + CLR_RSET

        if opts.get('network', False) and p.get('files',False):
            for i in p['files']:
                # deprecating before release: files is now only a list fd->inode, not an inode/mode tuple now
                if isinstance(p['files'][i], str):
                    p['files'][i] = ('socket:' + p['files'][i], 0)
                if p['files'][i][0].startswith('socket:') :
                    inode = p['files'][i][0].replace('socket:','')
                    sock = filedata['network'].get(inode,False)
                    if sock:
                        if str(sock[0]) == 'TCP' and not (opts.get('network_nolisten',False) and int(sock[3]) == 10):
                            print '\tTCP:   %36s     %36s    %s' % (sock[1], sock[2], TCP_STATES.get(int(sock[3]), ''))
                        elif str(sock[0]) == 'UDP':
                            print '\tUDP:   %36s     %36s' % (sock[1], sock[2])
                        elif str(sock[0]) == 'UNIX' and sock[1] and not opts.get('network_nolisten',False):
                            print '\tUNIX:   %36s' % sock[1]
                            
    if opts.get('mysql',False):
        if filedata.get('C-mysql',False):
            jso = filedata['C-mysql']
        else:
            sqllog = getNearestLog(int(filedata['START']),type = 'mysql', maxdistance = 10)
            if sqllog:
                jso = read_json(sqllog)
            else:
                jso = False
        if jso and jso.get('processlist',False):
            print ""            
            print "MySQL Processes (recorded at " + str(datetime.fromtimestamp(int(jso['START']))) + "): "
            ptbl = jso['processlist']
            for k, v in enumerate(ptbl):
                if len(ptbl[k]) < 8:
                    ptbl[k].append('')            
            widths = [ reduce(lambda a,b: max(len(str(a)),len(str(b))), x) for x in zip(*ptbl) ]
            rct = 0
            for row in ptbl:
                rct+=1
                for ind, col in enumerate(row):
                    print '| ' + str(col).ljust(widths[ind]+1).decode('string_escape') + ' ',
                print '|'
                if rct == 1:
                    print '-'*(sum([ x + 5 for x in widths], 1))
        elif jso.get('error'):
            print "%s\nMYSQL ERROR AT %s: %s%s" % (CLR_RED, str(datetime.fromtimestamp(int(jso['START']))), jso['error'],CLR_RSET)
        else:
            if not USE_MYSQLDB:
                print "No MySQL information was available.  Most likely MySQL was down, didn't respond before a timeout, or had too many connections.  Run 'easy_install python-MySQL' to enable full mysql error messages."
            else:
                print "No MySQL information was available.  There may have been a timeout in the MySQL monitor thread or another error.  Check %s/syssnap.err and report a bug if there is a python error there." % CFG_LOG_DIRECTORY
    if opts.get('ubc',False) and filedata.get('beancounters', False):
        print "\nUser beancounters:"
        print "\tRESOURCE                held      maxheld              barrier                limit              failcnt"
        for k, v in filedata['beancounters'].iteritems():
            try:
                if float(v[2]) > 0:
                    uhoh = float(v[0]) / float(v[2])
                else:
                    uhoh = 0
                if int(v[4]) > 0 or uhoh > .9:
                    print CLR_RED,
                elif uhoh > .7:
                    print CLR_YELLOW,
                print "\t" + k.ljust(15) + ' ' + v[0].rjust(12) + ' ' + v[1].rjust(12) + ' ' + v[2].rjust(20) + ' ' + v[3].rjust(20) + ' ' + v[4].rjust(20)
                if int(v[4]) > 0 or uhoh > .7:
                    print CLR_RSET,
            except IndexError:
                pass # bad row picked up without all the fields


def dumpProcessData(logdata):
	return 0 # placeholder
	dumpDStruct(logdata, 0)

def dumpDStruct(data, rct):
	for d in data:
		if isinstance(d, list):
			print "%s%s:" % ("\t"*rct, d)
			dumpDStruct(data[d],rct + 1)
		


def parentKeyProcesses(procs):
    keys = {}
    proctable = dict([ (int(p['pid']), p) for p in procs])
    for p in procs:
        p0 = p['pid']
        k = str(p['pid']) # str(p['pid'])
        try:
            while int(p['parent']) > 0:
                p = proctable[int(p['parent'])]
                k = str(p['pid']) + '-' + str(k)
        except (KeyError, ValueError):
            k = str(p0)
        keys[str(p0)] = k
    return keys

     
def gigaprint(n,k = False):
    if k:
        ends = ['M', 'G']
    else:
        ends = ['K','M','G']
    n = int(n)
    if n > 1073741824 and not k:
        return str(n / 1073741824) + ends[2]
    elif n > 1048576:
        return str(n / 1048576) + ends[1]
    elif n > 1024:
        return str(n / 1024) + ends[0]
    else:
        return str(n)

def timePrint(sec):
    min = int(sec / 60)
    sec = sec - min*60
    if min > 999999:
        return str(min)
    if min > 0:
        sec = int(sec)
    else:
        return str(sec)
    return str(min) + ':' + str(sec).zfill(2)

def setTimezone():
    os.environ['TZ'] = CFG_TZ
    time.tzset()

def showStatistics(stime, *shopts, **opts):
    # preliminary stats stuff
    if sys.stdout.isatty():
        print "Generating stats, this may take minute for un-cached days...",
    checkAndArchive() # this is a good place to force an archive since stats take a little while anyway
    # stat file for that day already?
    ltime = 0
    lines = {}
    if opts.get('range',False):
        START = opts['range'][0]
        END = opts['range'][1]
    else:
        START = stime
        END = stime + 86400
    headers = False
    if os.path.exists('%s/stats/%s.txt' % (CFG_LOG_DIRECTORY, stime)):
        f = open('%s/stats/%s.txt' % (CFG_LOG_DIRECTORY, stime), 'r')
        headers = f.readline().split()
        for l in f.readlines():
            l = l.split()
            ubc_failct = 0
            if CFG_UBC and 'UBC_TOT' in l:
                u_n = l.index('UBC_TOT')
                ubc_failct = l[u_n+1]
                del l[u_n+1]
                del l[u_n]
            ltime = int(l[0])
            lines[ltime] = dict(zip(headers,l))
            lines[ltime]['time'] = int(l[0]) #ZZ time.strftime('%H:%M',time.localtime(int(l[0])))
            if CFG_UBC:
                lines[ltime]['ubc_fails_tot'] = int(ubc_failct)
        # if last was pretty close to the end, don't bother with the next part, it got all the time for the day for sure
        f.close()
    if not headers:
        headers = getStatHeaders()
    if ltime < stime + 86280:
        tmid = midnight(timestamp=stime)
        if os.path.exists('%s/arch-%s' % (CFG_LOG_DIRECTORY, tmid)):
            d = glob.glob('%s/arch-%s/proc-*' % (CFG_LOG_DIRECTORY, tmid))
        else:
            d = glob.glob('%s/proc-*' % CFG_LOG_DIRECTORY)
        fistats = None
        for i in d:
            it = int(i.split('-')[-1].split('.')[0])
            if it >= stime and it < stime + 86400 and lines.get(it, False) == False:
                fistats = getStatsFromFile(i)
                if fistats:
                    lines[it] = fistats

    if CFG_UBC:
        lastubc = getUbcCount(stime - 60)
    else:
        lastubc = 0
    if len(lines) == 0:
        print "Error: there are no statistics available for the chosen timeframe."
        return False
    for l_k in lines:
        lines[l_k]['time'] = time.strftime('%H:%M',time.localtime(int(lines[l_k]['time'])))
    outp = ''
    header_lens = dict([ (headers[i], max(len(headers[i])+1,8)) for i in range(len(headers)) ])
    for i,j in enumerate(headers):
        outp += j.rjust(header_lens[j])
    outp = outp + "\n"

    outpf = outp # for writing to file
    lasth = stime - stime % 3600
    if START > stime + 300:
        lasth = START - START % 3600

    outpc = 0
    for lnum, l in enumerate(sorted(lines)):
        if CFG_UBC == 1 and lines[l].get('ubc_fails_tot',False):
            lines[l]['ubc_fails'] = 0
            lines[l]['ubc_fails'] = lines[l]['ubc_fails_tot'] - lastubc
            lastubc = lines[l]['ubc_fails_tot']
        if not opts.get('skipheaders',False) and lasth <= (l - 10800) and l > (START + 120) and l < (END - 120):
            if lnum > 2:
                outp += '\n'
                lasth = l - l % 3600
                for i,j in enumerate(headers):
                    if j in ['user1','user2','user3']:
                        outp += ' %s' % j.ljust(8)
                    else:
                        outp += j.rjust(header_lens[j])
                outp += '\n'
            else:
                lasth = l - l % 3600 
        nl = ''.join([ statjust(x, lines[l].get(x,'-'), header_lens[x]) for x in headers ]) + "\n"
        if l >= START and l <= END:
            outpc += 1
            outp = outp + nl
        if CFG_UBC == 1:
            outpf = '%s%s %s UBC_TOT %s\n' % (outpf, str(l), nl[8:].rstrip(), lines[l]['ubc_fails_tot'])
        else:
            outpf = '%s%s %s' % (outpf, str(l), nl[8:])
    if sys.stdout.isatty():
        print "\r"                   # cover up the generation message in case stuff gets pasted
    if outpc > 0:
        print outp
    else:
        print "WARNING: There are no logs available for this period.  Type sys-snap -l to get a list of available logs."
    if not os.path.exists('%s/stats' % CFG_LOG_DIRECTORY):
        os.makedirs('%s/stats' % CFG_LOG_DIRECTORY)
    f = open('%s/stats/%s.txt' % (CFG_LOG_DIRECTORY,stime), 'w')
    f.write(outpf)
    f.close()

def statjust(key, val, length):
    if key in ['user1','user2','user3']:
        if isinstance(val,tuple):
            val = val[0]
        return ' %s' % (('%s' % val).ljust(length + 1))
    return str(val).rjust(length)

def getStatHeaders(sorter=False):
    'basically pulls the current list of fields for stats, used in case stats change in the future for backwards compatibility with older files, sorter provides a key=># dict for sorting fields'
    headers = ['time','load1','load5','memused','buffers','cached','memfree','swapfree','procs','proc_rstate','proc_dstate','proc_zstate','net_tot','net_http','net_syn','net_estab','net_udp','mysql']
    if CFG_UBC:
        headers.append('ubc_fails')
    headers.extend(['user1','user2','user3'])
    if sorter:
        return dict([ (v,k) for k, v in enumerate(headers) ])
    return headers

def getStatsFromFile(fi):
    j = read_json(fi)
    if not j:
        return None
    data = {}
    data['time'] = int(j['START']) # time.strftime('%H:%M',time.localtime(int(j['START'])))
    data['load1'] = j['sysinfo']['load1']
    data['load5'] = j['sysinfo']['load5']
    data['memused'] = (int(j['sysinfo']['MemTotal'].split()[0]) - int(j['sysinfo']['MemFree'].split()[0]))/1024
    data['buffers'] = (int(j['sysinfo'].get('Buffers','0').split()[0]))/1024
    data['cached']  = (int(j['sysinfo']['Cached'].split()[0]))/1024
    data['memfree'] = (int(j['sysinfo']['MemFree'].split()[0]) + data['buffers'] + data['cached'])/1024
    data['swapfree'] = (int(j['sysinfo']['SwapFree'].split()[0]))/1024
    data['procs'] = len(j['processes'])
    data['proc_rstate'] = 0
    data['proc_dstate'] = 0
    data['proc_zstate'] = 0
    #states
    for pr in j['processes']:
        if pr['state'] == 'S':
            continue
        elif pr['state'] == 'D':
            data['proc_dstate'] += 1
        elif pr['state'] == 'R':
            data['proc_rstate'] += 1
        elif pr['state'] == 'Z':
            data['proc_zstate'] += 1
    #net
    data['net_tot'] = 0
    data['net_http'] = 0
    data['net_syn'] = 0
    data['net_estab'] = 0
    data['net_udp'] = 0
    pstats = [ int(z['uid']) for z in j['processes'] if int(z['uid']) > 100 ]
    topusers = sorted([ (y, pstats.count(y)) for y in set(pstats) ], key=lambda x: -x[1])[:4]
    for i,k in enumerate(topusers):
        try:
            topusers[i] =  getpwuid(k[0])[0]
            if len(topusers[i]) > 8:
                topusers[i] = k[0]
        except KeyError: # catch getpwuid key error in case this picks up a user that isn't on the system anymore
            pass
    topusers = filter(lambda x: x != 'mailman', topusers)
    if len(topusers) < 3:
        topusers.extend(['-'] * (3 - len(topusers)))

    for i,k in enumerate(topusers):
        data[ 'user%s' % (i+1) ] = k
    for i in j['network']:
        if j['network'][i][0] in ['TCP', 'UDP']:
            data['net_tot']+=1
            if (j['network'][i][1][-3:] == ':80' or j['network'][i][1][-4:] == ':443'):
                if len(j['network'][i]) == 4 and j['network'][i][3] != 10:
                    data['net_http'] += 1
            if j['network'][i][0] == 'UDP':
                data['net_udp'] += 1
            else:
                if j['network'][i][3] == 3 or j['network'][i][3] == 2:
                    data['net_syn'] += 1
                elif j['network'][i][3] == 1:
                    data['net_estab'] += 1
    try:
        data['mysql'] = len(j['C-mysql']['processlist'])- 1
    except (KeyError, TypeError):
        data['mysql'] = '?'
    if CFG_UBC == 1 and j.get('beancounters',False):
        data['ubc_fails'] = 0
        data['ubc_fails_tot'] = sum([ int(j['beancounters'][n][4]) for n in j['beancounters'] ])
    return data

def getUbcCount(stime):
    ' just pulls the UBC data from that time'
    log = getNearestLog(stime)
    if log:
        js = read_json(log)
        if not js:
            return False
        ubc = js.get('beancounters', False)
        if ubc:
            return sum([ int(ubc[x][4]) for x in ubc ])
    return False

# archive/cleaner functions
def checkAndArchive():
    'checks for any files older than current day in CFG_LOG_DIRECTORY and moves them'
    mid = midnight()
    fnlist = filter(lambda x: x[:5] == 'proc-', os.listdir(CFG_LOG_DIRECTORY)) 
    flist = [ procfileToTime(x) for x in fnlist ]
    if len(flist) == 0:
        return True
    first = min(flist)
    offset = mid % 86400
    timediff = (mid - first) / 86400
    if (mid - first) % 86400 > 0:
        timediff += 1
    archdays = [ mid - 86400 * (x) for x in range(timediff + 1) ]
    for day in archdays:
        if not os.path.exists('%s/arch-%s' % (CFG_LOG_DIRECTORY,day)):
            os.mkdir('%s/arch-%s' % (CFG_LOG_DIRECTORY,day))
    for k,v in enumerate(flist):
        td = v - (v - offset) % 86400
        print "renaming %s/%s into %s (for %s)" % (CFG_LOG_DIRECTORY, fnlist[k], td, v)
        os.rename('%s/%s' % (CFG_LOG_DIRECTORY, fnlist[k]), '%s/arch-%s/%s' % (CFG_LOG_DIRECTORY, td, fnlist[k]) )

def removeOldLogs():
    lim = int(CFG_LOG_RETENTION)
    slurp = sorted(glob.glob('%s/arch-*' % CFG_LOG_DIRECTORY), key=lambda x: int(x.split('-')[-1]) )
    if len(slurp) <= CFG_LOG_RETENTION:
        return False
    slurp = slurp[:-lim]
    for f in slurp:
        if not os.path.exists('%s/saveme' % f) and time.time() - int(f.split('-')[-1]) > 86400 * lim:
            filelist = os.listdir(f)
            for fl in filelist:
                #print "Deleting file %s" % fl
                os.unlink('%s/%s' % (f, fl))
            #print "Deleting folder %s" % f
            os.rmdir(f)



def showLogs():
    slurp = sorted(glob.glob('%s/arch-*' % CFG_LOG_DIRECTORY), key=lambda x: int(x.split('-')[-1]) )
    if len(slurp) == 0:
        print "There are no logs available."
        sys.exit()
    print "Logs are available from the following days: "
    for i in slurp:
        extinfo = ''
        glurp = sorted(glob.glob('%s/proc-*' % i))
        if len(glurp) == 0:
            continue
        elif len(glurp) == 1:
            logtime = int(glurp[0].split('-')[-1].split('.')[0])
            extinfo = " - One log - %s" % time.strftime('%H:%M', time.localtime( logtime ))
        else:
            logtime = int(glurp[0].split('-')[-1].split('.')[0])
            logtime2 = int(glurp[-1].split('-')[-1].split('.')[0])
            extinfo = " - %s logs from %s to %s" % (len(glurp), time.strftime('%H:%M', time.localtime( logtime )), time.strftime('%H:%M', time.localtime( logtime2 )))
        stime = int(i.split('-')[-1])
        svd = ''
        if os.path.exists('%s/saveme' % i):
            svd = '[saved]'
        elif time.time() - stime > int(CFG_LOG_RETENTION) * 86400:
            svd = '[old]'
        print '%s - %s %s%s' % (time.strftime('%b %d %Y', time.localtime(stime)), i, svd, extinfo)
    print ''

def saveLog(day=None):
    if day:
        d = day.split('/')
        if len(d) != 2 and len(d) != 3:
            print "Invalid date: %s" % day
            sys.exit()
        if len(d) == 3 and (not d[2].isdigit() or int(d[2]) < 2000):
            print "Invalid date (%s): year should be over 2000." % day
        if not d[0].isdigit() or not d[1].isdigit():
            print "Invalid date: %s" % day
        if len(d) == 3:
            year = int(d[2])
        else:
            dt = datetime.today()
            year = dt.year
        dt = datetime(year,int(d[0]),int(d[1]),0,0,0)
    else:
        dt = datetime.today()
        dt = datetime(dt.year,dt.hour,dt.minute,0,0,0)
    tstamp = int(time.mktime(dt.timetuple()))
    if os.path.exists('%s/arch-%s' % (CFG_LOG_DIRECTORY, tstamp)):
        f = open('%s/arch-%s/saveme' % (CFG_LOG_DIRECTORY, tstamp),'w')
        f.close()
        print "set logs for %s/%s/%s to not be deleted by sys-snap automatically." % (dt.month,dt.day,dt.year)
    else:
        print "There are no logs for %s/%s/%s." % (dt.month,dt.day,dt.year) 

def unsaveLog(day):
    d = day.split('/')
    if len(d) != 2 and len(d) != 3:
        print "Invalid date: %s" % day
        sys.exit()
    if len(d) == 3 and (not d[2].isdigit() or int(d[2]) < 2000):
        print "Invalid date (%s): year should be over 2000." % day
    if not d[0].isdigit() or not d[1].isdigit():
        print "Invalid date: %s" % day
    if len(d) == 3:
        year = int(d[2])
    else:
        dt = datetime.today()
        year = dt.year
    dt = datetime(year,int(d[0]),int(d[1]),0,0,0)
    tstamp = int(time.mktime(dt.timetuple()))
    if os.path.exists('%s/arch-%s/saveme' % (CFG_LOG_DIRECTORY, tstamp)):
        os.unlink('%s/arch-%s/saveme' % (CFG_LOG_DIRECTORY, tstamp))
        print "set logs for %s/%s/%s to be deleted by normal time limits again." % (dt.month,dt.day,dt.year)
    else:
        print "There are no logs for %s/%s/%s." % (dt.month,dt.day,dt.year)


def midnight(day=-1, month=-1, year=-1, timestamp = -1):
    'return timestamp for midnight of given day, uses todays attributes for ones not given'
    if timestamp > -1:
        d = datetime.fromtimestamp(timestamp)
    else:
        d = datetime.today()
    if day == -1 or month == -1 or year == -1:
        if day == -1:
            day = d.day
        if month == -1:
            month = d.month
        if year == -1:
            year = d.year
    return int(time.mktime(datetime(year, month, day, 0, 0, 0).timetuple()))


def procfileToTime(file):
    if file.find('/') > -1:
        file = file.split('/')[-1]
    return int(file[5:].split('.')[0])

def datePrint(timestamp, seconds = False):
    d = datetime.fromtimestamp(timestamp)
    if time.time() - timestamp < 86400:
        s = str(d.hour).zfill(2) + ':' + str(d.minute).zfill(2)
    else:
        s = '%s/%s-%s:%s' % (d.month, d.day, str(d.hour).zfill(2), str(d.minute).zfill(2))
    if seconds:
        s = '%s:%s' % (s, str(d.second).zfill(2))
    return s

def getDiskSpace(dir=None):
    if dir==None:
        dir=CFG_LOG_DIRECTORY
    try:
        vfs = os.statvfs(CFG_LOG_DIRECTORY)
    except OSError:
        return False
    return (vfs.f_bavail * vfs.f_bsize)
    
def usage():
    print "%ssys-snap - system snapshot generator (python edition)%s" % (CLR_BOLD, CLR_RSETB)
    print "\tUsage: %s [options]" % sys.argv[0]
    print "\n"
    print "%sRUNNING AS A DAEMON/SERVICE%s\n" % (CLR_BOLD, CLR_RSETB)
    print "%s --start [ options ]%s" % (CLR_BOLD, CLR_RSETB)
    print "\tStart as a daemon to collect snapshot data.\n"
    
    print "%sStart options%s" % (CLR_BOLD, CLR_RSETB)
    print "%s--load <number|numberx>%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tSet load threshold for recording logs.  --load <number> sets minimum load\n\
    \tfor logging to number, adding an 'x' at the end will set it to multiply this\n\
    \tby the number of CPU cores in the server (--load 3x on a 4 core server will\n\
    \tonly record logs if the load is over 12 (or if memory threshold is set and hit).\n"
    
    print "%s--mem <number|number%%>%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tset memory threshold to only record if memory usage over <number> MB, or\n\
    \t<number>% usage.\n\nWARNING: Sometimes issues occur regardless of load or happen too fast,\n\
    \tso unless you're sure the problem only occurs with load spikes or are concerned\n\
    \tabout limited disk space, you should try avoiding these or setting them very low.\n"
    
    print "%s--compress%s" % (CLR_BOLD, CLR_RSETB)
    print "\tGzip logs as they are created to save space (uses more CPU, and a LOT more with stats).\n"
    
    print "%s--stop%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tStop sys-snap service.\n"
    
    print "%s--status%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tCheck service status.\n\n"
    
    print "%sREADING SNAPSHOTS%s\n" % (CLR_BOLD, CLR_RSETB)
    print "%sUsage: %s [options] [before] <date/time | current | reboot>%s\n" % ( CLR_BOLD, sys.argv[0], CLR_RSETB)
    
    print "\tTo view a snapshot, run %s with a date/time, or the keywords 'current' or 'reboot'.\n" % sys.argv[0]
    
    print "\tThe time accepts the following formats: \n"
    
    print "\t\t24 Hour time: 0:25, 20:00, etc. If you use a time later than the current time, it looks\n\t\tat yesterday's logs."
    print "\t\t12 hour time: 6:15 PM.  With both 12/24 hour you can also specify seconds (6:15:45 PM)."
    print "\t\tDates can be specified in m/d or m/d/y (with 4 or 2 digits for year)."
    print "\t\tAny of these are acceptable: 7/29/2012 5:00, 7/29 5:00, 5:00 7/29/12."
    print "\t\tThe keyword %scurrent%s can be used instead to look for the log near the current time." % (CLR_BOLD, CLR_RSETB)
    print "\t\tThe keyword %sreboot%s will automatically use the time the server was last rebooted." % (CLR_BOLD, CLR_RSETB)
    print "\t\tNormally, sys-snap searches for the log closest to the time entered.  Using the keyword %sbefore%s\n\
    \t\tin the command will search for the closest before the specified time instead \n\
    \t\t(EX. %s before 7:15 PM)" % (CLR_BOLD, CLR_RSETB, sys.argv[0])

    print "\t\t'-' or '.':  If sys-snap is called using a - or ., it will use live data instead of reading logs (useful for live monitoring)."

    print "\n"
    
    print "%sREADING SNAPSHOT OPTIONS%s\n" % (CLR_BOLD, CLR_RSETB)
    
    print "%s--extended or --ext or -e%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tShow additional information for each process - common environmental variables, working directory,\n\
    \tnumber of threads, I/O operations, context switches, child CPU usage, etc.\n"

    print "%s-E%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tThis behaves just like -e, however for anything that has a REQUEST_URI environmental variable (normally php/cgi scripts),\n\
    \tit shows more user-friendly output about the HTTP/HTTPS request.\n"
    
    print "%s--network or --net or -n%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tShow information about sockets attached to each process (similar to netstat, but merged with ps aux).\n"

    print "%s-N%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tThis is the same as --network/-n/--net, however it doesn't show listening TCP connections or unix sockets.\n"    
    
    print "%s--mysql or --sql or -m%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tShow mysql process list for the time if one is available.\n"
    
    print "%s--ubc%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tShow /proc/user_beancounters (only on VPSes).\n"
    
    print "%s--all or -a%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tShow all extended options.\n"

    print "%s--no-headers%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tNormally sys-snap shows basic load/memory info and header lines at the top - skip for easier parsing.\n"
    
    print "%s--sort or -s <sort field>%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\tNormally sys-snap shows data similarly to 'ps auxfw'."
    print "\tAlternatively, the process list can be sorted with --sort or -s (this works with the other options too).\n"
    print "\tFields available are:"
    
    print "\t\tcpu - cpu (percent usage)"
    print "\t\tcputime - cpu time (seconds used)"
    print "\t\tmem - memory (RSS) usage"
    print "\t\tvm - virtual memory size"
    print "\t\tstate - process state"
    print "\t\tnice - nice value"
    print "\t\tior - bytes read (note: this is not specific to disks so some processes like SSH show large values naturally."
    print "\t\tiow - bytes written (same note as ior)"
    print "\t\treads - number of system read() calls"
    print "\t\twrites - number of system write() calls"
    print "\t\tuser - process owner"
    print "\t\tchildren - amount of CPU time used by process children"
    
    print "\n"

    print "%sSTATISTICS (like sar)%s\n" % (CLR_BOLD, CLR_RSETB)
    print "%sUsage: %s [date] [hour|start hour-end hour [am|pm]]%s\n" % (CLR_BOLD, sys.argv[0], CLR_RSETB)
    print "sys-snap can show per-snapshot statistics (similar to sar).  The current version has no extra\n\
           optional arguments, it simply takes a date and/or time range to show stats for.  Keep in mind\n\
           that doing a full day at once will produce a lot of output (typically around 1500 lines).\n"
    print "Examples:\n"
    print "\t%s 5/1 - show statistics for all of May 1st this year" % sys.argv[0]
    print "\t%s 5/1 2 PM (or %s 5/1 14) - show stats for the 2:00 PM hour on May 1" % (sys.argv[0], sys.argv[0])
    print "\t%s 5/1 2-5 PM - show stats for May 1 from 2 to 5 PM" % sys.argv[0]
    print "\t%s 9-5 - show stats for today, from 9 am to 5 pm" % sys.argv[0]

    print "\n"
    print "%sSTATISTICS FIELDS%s\n" % (CLR_BOLD, CLR_RSETB)
    print "\t%sload1, load5:%s\t\t the 1 and 5 minute load averages for the snapshot" % (CLR_BOLD, CLR_RSETB)
    print "\t%smemused:%s\t\t total memory used (includes buffers and caches)" % (CLR_BOLD, CLR_RSETB)
    print "\t%sbuffers, cached:%s\t buffers and cached memory (same as in free -m)" % (CLR_BOLD, CLR_RSETB)
    print "\t%smemfree:%s\t\t total actual free memory (buffers and caches counted in this number)" % (CLR_BOLD, CLR_RSETB)
    print "\t%sswapfree:%s\t\t free swap space" % (CLR_BOLD, CLR_RSETB)
    print "\t%sprocs:%s\t\t\t total number of processes on system" % (CLR_BOLD, CLR_RSETB)
    print "\t%sproc_rstate:%s\t\t processes active in the running state" % (CLR_BOLD, CLR_RSETB)
    print "\t%sproc_dstate:%s\t\t processes in uninterruptible sleep (usually due to I/O)" % (CLR_BOLD, CLR_RSETB)
    print "\t%sproc_zstate:%s\t\t processes in Z state (defunct)" % (CLR_BOLD, CLR_RSETB)
    print "\t%snet_tot:%s\t\t total network connections" % (CLR_BOLD, CLR_RSETB)
    print "\t%snet_http:%s\t\t connections to port 80 and 443" % (CLR_BOLD, CLR_RSETB)
    print "\t%snet_syn:%s\t\t connections in SYN_SENT or SYN_RECV state" % (CLR_BOLD, CLR_RSETB)
    print "\t%snet_estab:%s\t\t Established TCP connections" % (CLR_BOLD, CLR_RSETB)
    print "\t%snet_udp:%s\t\t UDP connections" % (CLR_BOLD, CLR_RSETB)
    print "\t%subc_fails:%s\t\t User beancounter resource hits (VPS only)" % (CLR_BOLD, CLR_RSETB)
    print "\t%suser1,2,3:%s\t\t The top 3 users by process count on the server." % (CLR_BOLD, CLR_RSETB)

    print "\n"
    print "%sUTILITY FUNCTIONS%s\n" % (CLR_BOLD, CLR_RSETB)
    print "%s--list%s\n\tList all days for which logs are currently saved (and show the folder names for those days).\n" % (CLR_BOLD, CLR_RSETB)
    print "%s--save <date>%s\n\tMark a day (using numeric format month/day or month/day/year) to save logs from being deleted by sys-snap permanently.\n" % (CLR_BOLD, CLR_RSETB)
    print "%s--unsave <date>%s\n\tUnmark a day (using numeric format month/day or month/day/year) so that its logs are no longer held from deletion.\n" % (CLR_BOLD, CLR_RSETB)
    print "%s--cron%s\n\tRun cron tasks: currently ensures archives are organized and deletes logs older than retention interval set in top of script.\n" % (CLR_BOLD, CLR_RSETB)

    print "\n"
    print "%sGENERAL OPTIONS%s\n" % (CLR_BOLD, CLR_RSETB)
    print "%s-C or --nocolor%s\n\tDisable use of colors in script output.\n\tThis can also be set with the environmental variable NOCOLOR." % (CLR_BOLD, CLR_RSETB)

    print "\n"
    print "%sSERVICE SCRIPT%s\n" % (CLR_BOLD, CLR_RSETB)
    print "sys-snap's daemon can be controlled via --start/--stop or via an init script with service sys-snap start, service sys-snap stop, and service sys-snap status."
    print "The init script can also be added to chkconfig (chkconfig --add sys-snap) if you wish sys-snap to always automatically run."

    print "\n"
    print "%sSEE ALSO%s\n\t%stwirlingbaton%s(3), %stput%s(1)\n" % (CLR_BOLD, CLR_RSETB, CLR_BOLD, CLR_RSETB, CLR_BOLD, CLR_RSETB)



# start main program
if __name__ == '__main__':
    MAIN_OPT = None
    CFG_NO_HEADERS = False
    display_opts = {}


    cfgp = ConfigParser.RawConfigParser()
    if os.path.exists('/etc/sys-snap.conf'):
        cfgp.read('/etc/sys-snap.conf')
    else:
        cfgp = None

    if cfgp:
        for k, v in cfgp.items('main'):
            if k == 'log_dir':
                try:
                    if os.path.exists(v) and os.path.isdir(v):
                        if v[-1] != '/':
                            v = '%s/' % v
                        CFG_LOG_DIRECTORY = '%sSYS-SNAP' % v
                        if not os.path.exists(CFG_LOG_DIRECTORY):
                            os.makedirs(CFG_LOG_DIRECTORY)
                    else:
                        print "Path does not exist or is not a directory: %s" % v
                except OSError:
                    print "Error accessing directory %s: using default of %s" % (v, CFG_LOG_DIRECTORY)
            elif k == 'compression':
                if v == '1' or v.lower() in ['true', 'yes', 'y']:
                    COMPRESS_STUFF = 1
            elif k == 'log_retention':
                if v.isdigit():
                    v = int(v)
                    if v < 1 or v > 100:
                        print "Log retention should be a number from 2 to 100 (days retained): using default of %s" % CFG_LOG_RETENTION
                    else:
                        CFG_LOG_RETENTION = v
                else:
                    print "Invalid value for log retention: using default of %s" % CFG_LOG_RETENTION
            elif k == 'skip_unix_sockets':
                if k == "1":
                    CFG_SKIP_UNIX_SOCKETS = 1



    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hCvaeEnNmlSs:rui:', ['list', 'daemon', 'start', 'load=','mem=','stop', 'minsql', 'status','ps','ext','no-headers','noheaders','save=','unsave=',
                                                  'net', 'network', 'sql', 'mysql','sort=','test','ubc','all', 'version', 'help','interval','cron','cst', 'log-directory=','install-checks','nocolor',
                                                  'seconds','dump'])
    except getopt.GetoptError:
        print "Invalid arguments, %s.  For usage, type sys-snap -h." % sys.exc_info()[1]
        sys.exit(1)
    # handle TZ stuff
    if os.environ.get('TZ',False):
        CFG_TZ = os.environ['TZ']
        del os.environ['TZ']
        time.tzset()

    for o, a in opts:
        if o == '-l' or o == '--list':
            showLogs()
            sys.exit()
        elif o == '--save':
            saveLog(a)
            sys.exit(0)
        elif o == '--unsave':
            unsaveLog(a)
            sys.exit(0)
        elif o == '--install-checks':
            dspace = getDiskSpace()
            if dspace < 2147483648:
                print ("%sWARNING:%s The location you chose for logs %s only has %s free.  \n"
                "It is recommended to use a partition with at least 2 GB free.\n"
                "Please edit /etc/sys-snap.conf to change this and then type service sys-snap start to start sys-snappy.") \
                % (CLR_BOLD, CLR_RSETB, CFG_LOG_DIRECTORY, gigaprint(dspace))
                sys.exit(2)
            sys.exit(0)
        elif o == '--daemon' or o == '--start':
            pid = getDaemonPID()
            if pid == None:
                MAIN_OPT = 'daemon'
            else:
                print "Daemon already running [pid " + str(pid) + "].  Use --stop first."
                os._exit(0)
        elif o == '--load':
            try:
                if (a.endswith('x')):
                    a = float(a.strip('x'))
                    if a > 0.0:
                        cpus = 0
                        fp = open('/proc/cpuinfo','r')
                        for line in fp.readlines():
                            if line.startswith('processor'):
                                cpus+=1
                        a = a * cpus
                        fp.close()
                print "Setting load threshold for logging to %s" % float(a)
                CFG_PROC_MIN_LOAD = float(a)
            except ValueError:
                print "Invalid input for load, should be a floating point or integer number, or one ending with x to work with CPU multipliers (--load 1.5x means minimum load 1.5*number of processors)"
        elif o == '--mem':
            try:
                a = a.lower()
                if a.endswith('g'):
                    CFG_PROC_MIN_MEM = int(a.strip('g')) * 1048576
                elif a.endswith('m') or a.isdigit():
                    CFG_PROC_MIN_MEM = int(a.strip('m')) * 1024
                elif a.endswith('%'):
                    fp = open('/proc/meminfo','r')
                    mem = fp.readline().split()[1]
                    CFG_PROC_MIN_MEM = min(float(a.strip('%'))/100, 1.0) * int(mem)
                    fp.close()
                print "Setting logging threshold for memory to at least " + str(CFG_PROC_MIN_MEM / 1024) + "MB."
            except ValueError:
                print "Invalid input for --mem, must be in form of raw number (MB), M, G, or a percentage, eg --mem 500M or --mem 70%"
        elif o == '--stop':
            pid = getDaemonPID()
            if pid != None:
                print "Stopping sys-snap [PID " + str(pid) + "]"
                os.kill(pid, 15)
                for i in range(15):
                    time.sleep(.5)
                    if not os.path.exists('/proc/%s' % pid):
                        os._exit(0)
                    else:
                        print '.',
                os.kill(pid,9)
                os._exit(0)
            else:
                print "Could not find process to stop.  Please check process status manually."
            os._exit(0)
        elif o == '--status':
            pid, pidstat = getDaemonPID(True)
            if pid != None:
                if pidstat and pidstat in ['P','E', 'R']:
                    pidmap = {'P': 'starting up', 'E': 'not running (ERROR)', 'R': 'running'}
                    plabel = pidmap[pidstat]
                print "sys-snap is %s [ pid %s ]" % (plabel, pid)
                sys.exit(0)
            else:
                print "sys-snap is not running."
                sys.exit(1)
        elif o == '--minsql':
            if a.isdigit():
                CFG_MYSQL_MIN_QUERIES = int(a)
            else:
                print "Invalid value for --minsql, should be a positive number, the number of mysql processes required to log mysql activity."
        elif o == '--log-directory':
            CFG_LOG_DIRECTORY = a
        elif o == '--cron':
            MAIN_OPT = 'cron'
        elif o == '--no-headers' or o == '--noheaders':
            display_opts['skipheaders'] = True
        elif o == '--ext' or o == '--extended' or o == '-e':
            display_opts['extended'] = True
        elif o == '-E':
            display_opts['extended'] = True
            display_opts['extclean'] = True
        elif o == '--net' or o == '--network' or o == '-n':
            display_opts['network'] = True
        elif o == '-N':
            display_opts['network'] = True
            display_opts['network_nolisten'] = True
        elif o == '--sql' or o == '--mysql' or o == '-m':
            display_opts['mysql'] = True
        elif o == '-s' or o == '--sort':
            display_opts['sort'] = a
        elif o == '--test':
            MAIN_OPT = 'test'
        elif o == '--ubc' or o == '-u':
            display_opts['ubc'] = True
        elif o == '--all' or o == '-a':
            for k in ['extended','network','mysql','ubc']:
                display_opts[k] = True
        elif o == '--compress':
            COMPRESS_STUFF = 1
        elif o == '-h' or o == '--help':
            usage()
            sys.exit(0)
        elif o == '-v' or o == '--version':
            print "sys-snap [python edition] version %s" % SS_VERSION
            sys.exit(0)
        elif o == '-r':
            display_opts['repeat_headers'] = True
        elif o == '-C' or o == '--nocolor':
            CLR_RED = ""
            CLR_YELLOW = ""
            CLR_BLUE = ""
            CLR_LBLUE = ""
            CLR_GREEN = ""
            CLR_RSET = ""
        elif o == '-S' or o == '--seconds':
            display_opts['seconds'] = True
        elif o == '--dump':
			display_opts['DUMP'] = True
        elif o == '-i' or o == '--interval':
            if a.isdigit() and int(a) > 5 and int(a) < 7200:
                CFG_LOG_INTERVAL = int(a)
            else:
                print "Interval must be a number ( of seconds) between 5 and 7200 (2 hours)."
                sys.exit(1)
            
    # end parse opts, start parse args
    if len(args) > 0:
        import re
        from pwd import getpwuid
        try:
            import json as _realjson
        except ImportError:
            try:
                import cjson as _realjson
                _realjson.loads = _realjson.decode
                _realjson.dumps = _realjson.encode
            except ImportError:
                try:
                    import ujson as _realjson
                except ImportError:
                    _realjson = None
                
        if MAIN_OPT == None:
            MAIN_OPT = 'ps' # default ps style output etc for the log
        if re.match("[0-9]+\.txt(\.gz)?$", args[0]):
            # it's just a straight file
            if os.path.exists(CFG_LOG_DIRECTORY + '/' + args[0]):
                LogFile = args[0]
        elif len(args) == 1 and args[0] in ['.','-']:
            # straight snap, not getting anything from a log
            display_opts['logrequest'] = int(time.time())
            tmparse = ProcParser()
            tmparse.load()
            LogFileData = tmparse.encapsulate()
            if display_opts.get('mysql',False):
                tmsql = MySQLWatcher()
                tmsql.load()
                LogFileData['C-mysql'] = tmsql.encapsulate()
        else:
            LogTime = getDateFromArgs(args)
            if LogTime == None:
                sys.exit()
            elif LogTime < 0: # range
                LogTime = LogTime * - 1
                MAIN_OPT = 'stats'
            elif isinstance(LogTime, list):
                display_opts['range'] = LogTime
                logDT = datetime.fromtimestamp(LogTime[0]).timetuple()
                LogTime = int( time.mktime( datetime(logDT.tm_year, logDT.tm_mon, logDT.tm_mday, 0, 0, 0).timetuple() ) ) 
                MAIN_OPT = 'stats'
            else:
                if isinstance(LogTime, str) and LogTime[0] == '+':
                    LogTime = int(LogTime[1:])
                    LogFile = getNearestLog(LogTime + 30)
                    display_opts['logrequest'] = LogTime + 30
                else:
                    LogFile = getNearestLog(LogTime)
                    display_opts['logrequest'] = LogTime
                if LogFile:
                    lf_time = int(LogFile.split('-')[-1].split('.')[0])
                    if lf_time > 0:
                        writeReadCache(lf_time - CFG_LOG_INTERVAL, lf_time, lf_time + CFG_LOG_INTERVAL)
                if not LogFile:
                    print "Could not find a log file within 60 minutes of the designated time (" + str(datetime.fromtimestamp(LogTime)) + ")"
                    sys.exit()
                    # we have a log file, parse it in the main opts area
                LogFileData = read_json(LogFile)
                if not LogFileData:
                    sys.exit()   
        
    # after everything, if there is no main opt just do a regular snapshotting, no --daemon or anything
    if MAIN_OPT == None:
        #print "No main option given, running sys-snap in foreground.  Use --daemon to run in background."
        #syssnapLoop()
        MAIN_OPT = 'test'
    if MAIN_OPT == 'daemon':
        hname = os.uname()[1].split('.')
        if len(hname) > 10:
            hname.reverse()
            if hname[0] == 'br' or hname[0] == 'tr':
                hname.pop(0)
            if ((hname[1] == "hostgator" or hname[1] == "websitewelcome") and (hname[0] == "com" or hname[0] == "in")) or (hname[1] == "prodns" and hname[0] == "net"):
                if len(hname) == 3:
                    print "%sWARNING:%s This should not be run in daemon mode on shared servers!\n" % (CLR_BOLD, CLR_RSETB)
                    sys.exit(31)
        if sys.stdout.isatty():
            dspace = getDiskSpace()
            if dspace < 2147483648:
                print ("%sWARNING:%s The location you chose for logs %s only has %s free.  \n"
                "It is recommended to use a partition with at least 2 GB free.\n"
                "Please press ctrl-C and edit /etc/sys-snap.conf if you want to adjust the log directory.  Pausing 10 seconds...") \
                % (CLR_BOLD, CLR_RSETB,CFG_LOG_DIRECTORY,gigaprint(dspace))
                time.sleep(10)
        print "Forking into background for daemon mode..."
        daemonize()
        syssnapLoop(CFG_LOG_INTERVAL)
    elif MAIN_OPT == 'ps': # will have ps, lsof, etc type options and an all to combine the common ones, for now get the individual ones done first
        try:
			if display_opts.get('DUMP'):
				dumpProcessData(LogFileData)
			else:
				printProcessData(LogFileData, None, **display_opts)
        except IOError:
            if sys.exc_info()[1].errno == 32:
                sys.exit(0)
            else:
                sys.stderr.write(sys.exc_info()[1].strerror + "\n")
                sys.exit(1)
    elif MAIN_OPT == 'stats':
        try:
            showStatistics(LogTime, **display_opts)
        except IOError:
            if sys.exc_info()[1].errno == 32:
                sys.exit(0)
            else:
                sys.stderr.write(sys.exc_info()[1].strerror + "\n")
                sys.exit(1)
    elif MAIN_OPT == 'cron':
        # handle cleanup and archiving tasks
        checkAndArchive()
        removeOldLogs()
    elif MAIN_OPT == 'test':
        print "For usage, type %s -h or %s --help" % (sys.argv[0],sys.argv[0])
