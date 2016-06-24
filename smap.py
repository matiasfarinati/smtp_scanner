#
#    Title: SMAP
#    Authors: Esteban Carisimo, Matias Farinati & Sacha Van Straaten
#    Developed at: Facultad de Ingenieria de la Univeridad de Buenos Aires
#    Year: 2016
#    Asignament: Criptography and IT security
#    Code description:
#        Framework developed combining ZMap and nmap in order to weaknesses of SMTP.
#        Nmap provides which server are able to be used as Open Relay.
#        The rest of the code analyze SPF and Reverse DNS policies which can be also
#        useful as an authentication of the sender
#        

import dns.resolver
import sys
import os
import subprocess
import glob
import socket


class SMAP:
    def __init__(self,target_file):
        self.target_file=target_file
        self.dict={}
    def Reversecheck(self,output_file='Reverse_output.csv'):
        self.list_ptr=[]
        self.list_ip=[]
        
        fi=open('%s'%self.target_file,'r')
        fo=open('%s'%output_file,'w+')
        
        for line in fi:
            ip=line.strip()
            self.list_ip.append(ip)
            self.dict[ip]=[]
            A=dns.reversename.from_address("%s"%ip)
            try:
                R=dns.resolver.query(A, 'PTR')
                for r in R:
                    #print ip,r
                    #self.dict_ptr[ip]=r
                    self.dict[ip].append(r)
                    self.list_ptr.append((ip,str(r)))
                    fo.write('%s,%s\n'%(ip,str(r)))
            except:
                #print ip,'?'
                self.dict[ip].append('?')
                self.list_ptr.append((ip,'?'))
                fo.write('%s,%s\n'%(ip,'?'))
                
        fo.close()
        fi.close()
    
    def getReverseList(self):
        return self.list_ptr       
        
    def OpenRelayCheck(self,which='?',port=25):
        checkRelayList=[]
        OpenRelays=[]
        if which=='?':
            for MX in self.list_ptr:
                if MX[1]=='?':
                    checkRelayList.append(MX[0])  
        else:
            #"'ALL'
            checkRelayList=self.list_ip
        
        for ip in checkRelayList:
            cmd_subprocess='nmap --script smtp-open-relay.nse -p %s %s'%(port,ip)
            process = subprocess.Popen(cmd_subprocess.split(), stdout=subprocess.PIPE)
            #process.wait()
            output = process.communicate()[0] 
            if "Server is an open relay" in output:
                OpenRelays.append(ip)
                self.dict[ip].append('Open Relay')
            else:
                self.dict[ip].append('NOT Open Relay')
        return OpenRelays
            
    def printResults(self):
        if len(self.dict.keys())>0:
            print '\n (1) YOU MUST TAKE INTO ACCOUNT THAT TXT RECORDS MAY BE ALLOCATED IN UPPER NAME SERVERS\n'
            s=''
            for k in self.dict.keys():
                l=self.dict[k]
                s+='%s: '%k
                for l1 in l:
                    s+='%s '%l1
                s+='\n'
            print s
    def __str__(self):
        return 'This is the SMAP object and it has already been initialized'
        

    def DomainGraph(self,l,output_file):
        f=open('%s'%output_file,'w+')
        for e in l:
            ip=e[0]
            raw_domain=e[1]
            splitted_domain=raw_domain.split('.')
            domain=''
            for i in range(1,len(splitted_domain)-1):
                domain+='.%s'%splitted_domain[i]
            f.write('%s,%s\n'%(ip,domain))
        f.close()
        
    def SPFcheck(self,input_file,output_file='SPF_output.csv'):
        f=open('%s'%input_file,'r')
        fo=open('%s'%output_file,'w+')
        for line in f:
            ip,domain=line.strip().split(',')
            try:
                R=dns.resolver.query(domain, 'TXT')
                for r in R:
                    #print ip,r
                    #self.dict_ptr[ip]=r
                    self.dict[ip].append(r)
                    self.list_ptr.append((ip,str(r)))
                    fo.write('%s,%s\n'%(ip,str(r)))
            except:
                #print ip,'?'
                self.dict[ip].append('NO SPF(1)')
                self.list_ptr.append((ip,'?'))
                fo.write('%s,%s\n'%(ip,'?'))
        fo.close()
    
def CheckNetblock(nb):
    addr=nb.split('/')
    try:
        socket.inet_aton(addr[0])
        Legal=True
    except socket.error:
        Legal=False
    return Legal

def RemoveFirstLine(f):
    with open('%s'%f, 'r') as fin:
        data = fin.read().splitlines(True)
    with open('%s'%f, 'w') as fout:
        fout.writelines(data[1:])
    #os.system("sudo sed ':a;N;$!ba;s/saddr\n//g'%s>%s"%(f,f))

def Zmap(target_file,netblock):
    os.system('sudo zmap --verbosity=0 -p 25 -o %s %s > /dev/null 2>&1'%(target_file,netblock))
    RemoveFirstLine(target_file)

def main(target_file,port):
    #smap=SMAP('Puerto_25.txt')
    smap=SMAP(target_file)
    smap.Reversecheck()
    listReverse=smap.getReverseList()
    #print listReverse
    smap.DomainGraph(listReverse,'Reverse_domains.txt')
    smap.SPFcheck('Reverse_domains.txt')
    relays=smap.OpenRelayCheck('ALL',port)
    if len(relays)>0:
        f=open('OUTPUT_Relays.txt','w+')
        for r in relays:
            f.write('%s\n'%r)
        f.close()
    smap.printResults()
            

ayuda='en fase de pruebas'

#sys.argv[1]=numero de red o archivo objetivo
#sys.argv[2]=puerto

if len(sys.argv[1:])==0:
    print ayuda
else:
    if '-h' in sys.argv[1:]:
        print ayuda
    else:
        if len(sys.argv[1:])==2:
            flag=CheckNetblock(sys.argv[1])
            if flag:
                target_file='OUTPUT_Zmap.txt'
                Zmap(target_file,sys.argv[1])
                port=sys.argv[2]
            else:
                target_file=sys.argv[1]
                port=sys.argv[2]
                if glob.glob('%s'%target_file)!=None:
                    main(target_file,port)
                else:
                    print 'Target file does not exist'
            main(target_file,port)
        else:
            'Not enough arguments'
