import argparse
import socket
import select
import sys
import re
import traceback
from _thread import *
from datetime import datetime

parser = argparse.ArgumentParser()

parser.add_argument('--port',                help="Set listening port",                default=8888,                        type=int)
parser.add_argument('--max_conn',            help="Maximum allowed connections",       default=5,                           type=int)
parser.add_argument('--buffer_size',         help="Socket read buffer size",           default=8192,                        type=int)

args           = parser.parse_args()
terminateAll   = False

# --------------------------------------------------------------------------------------

def printStr (s, prefix=""):
    s = re.sub(r'(Authorization:\s\w*\s)(.*)', r'\1***REDACTED***', s, re.MULTILINE, re.IGNORECASE)
    print (f"{datetime.now().strftime('%m/%d/%Y, %H:%M:%S')} {prefix}::{s}")

# --------------------------------------------------------------------------------------

def start():    #Main Program
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2)  # timeout for listening so control+c signal can be handled
        sock.bind(('', args.port))
        sock.listen(args.max_conn)
        printStr("[*] Daemon started successfully [ %d ]" %(args.port))
    except Exception:
        printStr("[*] Unable to initialize socket", prefix="ERROR")
        printStr(Exception, prefix="ERROR")
        sys.exit(2)

    while True:
        try:
            try:
                conn, addr = sock.accept() #Accept connection from client browser
            except socket.timeout:
                continue
            except:
                raise

            start_new_thread (conn_string, (conn, addr)) #Starting a thread
        except KeyboardInterrupt:
            sock.close()
            printStr("[*] Shutdown")
            break

    terminateAll = False

# --------------------------------------------------------------------------------------

def conn_string (conn_src, addr_src):
    try:
        printStr (("="*4) + f" connected @ {str(conn_src.getsockname())} " + ("=" * 4))
        data = conn_src.recv(args.buffer_size)  # Receive client data
        try:
            printStr ("Socket Request Data:\n" + ("~"*60) +"\n" + str(data, encoding='utf-8') + "\n" + "~"*60)

            http_connect_relay = False
            connect_addrs = ''
            webserver_dst = ""
            port_dst      = -1
            first_line    = str(data.split(b'\n')[0], encoding='utf-8', errors='ignore')
            fl_cmd        = first_line.split(' ')
        except:
            try:
                conn_src.close()
            except: pass
            return

        # Parse the proxy request
        # GET http://blah.blah.blah.com:5550/device_info/hello.pl HTTP/1.1
        # determine if this is an HTTPS request with this type of header:
        # CONNECT blah.blah.com:5543 HTTP/1.1
        #...
        if fl_cmd[0].lower() == 'connect':
            http_connect_relay = True
            connect_addrs = fl_cmd[1]
            cnnt_parts    = connect_addrs.split(':')
            webserver_dst = cnnt_parts[0]
            port_dst      = int(cnnt_parts[1])
        else:
            # Otherwise treat as an old style GET header with the full URL request:
            #
            try:
                url = fl_cmd[1]
                http_pos = url.find('://') #Finding the position of ://
                if(http_pos==-1):
                    connect_addrs = url
                else:
                    connect_addrs = url[(http_pos+3):]

                port_pos = connect_addrs.find(':')
                webserver_pos = connect_addrs.find('/')

                if webserver_pos == -1:
                    webserver_pos = len(connect_addrs)
                if(port_pos == -1 or webserver_pos < port_pos):
                    port_dst = 80
                    webserver_dst = connect_addrs[:webserver_pos]
                else:
                    port_dst = int((connect_addrs[(port_pos+1):])[:webserver_pos-port_pos-1])
                    webserver_dst = connect_addrs[:port_pos]

                # remove the http(s)://blah.com/ url request from the data leaving only the path:
                #e.g http(s)://blah.com/runthis.py  -->  /runthis.py
                data = bytes(re.sub (r'(.*\s)(http(s|)://.*?)(/.*)', r"\1\4", str(data, encoding="utf-8")), 'utf-8')
            except:
                try:
                    conn_src.close()
                except: pass
                return

        printStr (f"Proxy to: {webserver_dst}:{str(port_dst)}")

        proxy_server (webserver_dst, port_dst, conn_src, addr_src, data, http_connect_relay)
    except Exception as err:
        printStr (f"Exception: {str(err)}", prefix="ERROR")
        printStr (traceback.format_exc(),   prefix="ERROR")




def proxy_server (webserver, port, conn_src, addr_src, data, http_connect_relay):
    try:
        # printStr(data)
        conn_dest = None
        conn_dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_dest.connect((webserver, port))
    except Exception as err:
        if conn_dest:
            conn_dest.close()

        if conn_src:
            conn_src.close()

        printStr(f"proxy_server(destination connect) Exception: {str(err)}", prefix="ERROR")
        printStr(traceback.format_exc(), prefix="ERROR")
        return

    try:
        if http_connect_relay:
            connected = b"HTTP/1.1 200 Connection Established\r\n\r\n\r\n"
            printStr("Enabling HTTP(S) Connect Relay:")
            printStr(str(connected, encoding='utf-8', errors='ignore'))
            conn_src.sendall(connected)
        else:
            conn_dest.sendall(data)

        conn_dest.setblocking(0)

        printStr(f"Starting transfer:: src socket:{str(conn_src.getsockname())}   dst socket:{str(conn_dest.getsockname())}")
        conn_src_data = b""
        conb_dst_data = b""
        terminate = False
        while not terminate and not terminateAll:
            inputs = [conn_src, conn_dest]
            outputs = []

            if len(conn_src_data) > 0:
                outputs.append(conn_src)

            if len(conb_dst_data) > 0:
                outputs.append(conn_dest)

            try:
                inputsReady, outputsReady, errorsReady = select.select(inputs, outputs, [], 1.0)
            except Exception as e:
                printStr("Exception : proxy_server[1] terminating with:", prefix="ERROR")
                printStr(e, prefix="ERROR")
                break

            for inp in inputsReady:
                if inp == conn_src:
                    try:
                        data = conn_src.recv(args.buffer_size)
                    except Exception as e:
                        printStr("Exception : proxy_server[conn_src.recv] terminating with:", prefix="ERROR")
                        printStr(e, prefix="ERROR")

                    if data != None:
                        if len(data) > 0:
                            conb_dst_data += data
                        else:
                            terminate = True
                elif inp == conn_dest:
                    try:
                        data = conn_dest.recv(args.buffer_size)
                    except Exception as e:
                        printStr("Exception : proxy_server[conn_dest.recv] terminating with:", prefix="ERROR")
                        printStr(e, prefix="ERROR")
                        terminate = True
                        break

                    if data != None:
                        if len(data) > 0:
                            conn_src_data += data
                        else:
                            terminate = True

            for out in outputsReady:
                if out == conn_src and len(conn_src_data) > 0:
                    bytes_written = conn_src.send(conn_src_data)
                    if bytes_written > 0:
                        conn_src_data = conn_src_data[bytes_written:]
                elif out == conn_dest and len(conb_dst_data) > 0:
                    bytes_written = conn_dest.send(conb_dst_data)
                    if bytes_written > 0:
                        conb_dst_data = conb_dst_data[bytes_written:]

        printStr(f"Transfer Ended:: src socket:{str(conn_src.getsockname())}   dst socket:{str(conn_dest.getsockname())}")
        conn_src.close()
        conn_dest.close()
    except Exception as err:
        if conn_dest:
            conn_dest.close()

        if conn_src:
            conn_src.close()

        printStr(f"proxy_server (relay) Exception: {str(err)}", prefix="ERROR")
        printStr(traceback.format_exc(), prefix="ERROR")
        return

if __name__== "__main__":
    start()