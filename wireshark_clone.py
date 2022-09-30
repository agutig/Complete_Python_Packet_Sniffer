from distutils.command.clean import clean
import socket ,ctypes, sys ,elevate


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

print(is_admin())

def sniffer():
    translate =''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    
    def dump(src, length=16):
        result=''
        while src:
            s,src = src[:length],src[length:]
            hex = ' '.join(["%02X"%ord(x) for x in s])
            s = s.translate(translate)
            result += "%-*s %s\n" % (length*3,hex,s)
        return result
    
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    L=0
    while 1:
        L = L + 1
        raw = s.recv(16000)
        print("========================================================================")
        print("Paquete: "+str(L))
        print("========================================================================")
        print(dump(raw))

if is_admin():
    # Code of your program here
    sniffer()
else:
    # Re-run the program with admin rights
    elevate.elevate()
 