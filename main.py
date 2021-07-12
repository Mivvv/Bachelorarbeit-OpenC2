import json
import subprocess
from subprocess import check_output
import os
import getpass
import requests
import sys
import ast
import time
# certain functions of socket only supported on unix
import socket

#region Helper
# functions that help us find the right variables

# return logical name of network card
def returnNetName():
    cmd = "sudo ip link show".split()
    card = str(subprocess.Popen(cmd,stderr=subprocess.PIPE,stdout=subprocess.PIPE).communicate()[0])
    ind = card.find("n2")
    #ind = card.find("2:")
    if(ind >= 0):
        name = card[ind+4:]
        ind = name.find(":")
        if(ind >= 0):
            name = name[:ind]
            return name
        else:
            return ""
    else:
        return ""

# return our current mac address
def returnMac():
    cmd = "sudo ip link show".split()
    card = str(subprocess.Popen(cmd,stderr=subprocess.PIPE,stdout=subprocess.PIPE).communicate()[0])
    ind = card.find("link/ether")
    if(ind >= 0):
        name = card[ind+11:]
        ind = name.find("brd")
        if(ind >= 0):
            name = name[:ind-1]
            return name
        else:
            return ""
        
    else:
        return ""

# returns the pairs our profile supports
def get_Pairs():
    deny_P = {"deny": ["ipv4_net","ipv6_net","mac_addr","email_addr"]}
    contain_P = {"contain": ["mac_addr"]}
    query_P = {"query": ["features"]}
    delete_P = {"delete": ["file"]}
    detonate_P = {"detonate": ["file"]}
    pairs = dict()
    pairs.update(deny_P)
    pairs.update(contain_P)
    pairs.update(query_P)
    pairs.update(delete_P)
    pairs.update(detonate_P)
    return pairs
#endregion
actions = {"query","deny","contain","delete","detonate"}
targets = {"email_addr","features","file","ipv4_net","ipv6_net","mac_addr"}
pairs = get_Pairs()
response = {"status","status_test","results"}
status = {"200","401","500","501"}
comm = sys.argv[1]
user = getpass.getuser()

# test if the IP is valid both for IPv4 and 6
def validateIPv4(ipv4):
    try:
        socket.inet_pton(socket.AF_INET, ipv4)
    except:
        try:
            socket.inet_aton(ipv4)
        except socket.error:
            return False
    return True

def validateIPv6(ipv6):
    try:
        socket.inet_pton(socket.AF_INET6, ipv6)
    except:
        return False
    return True

# testing variables
locLog = '/home/'+user+'/Desktop/log.txt'

# main function that is called
def watchdog():
    try:
        C2_command = json.loads(comm)
        if C2_command is not None:
            valid = validate(C2_command)
            if(valid):
                execute(C2_command)
            else:
                throw_501()
        else:
            throw_500()
    except:
        throw_500()
 







# only general validation, asking for the two required parts of an OpenC2 command
# further validation will be done later and will limit the avaiable commands.
def validate(c2):
    if "action" in c2 and "target" in c2:
        if c2["action"] in pairs:
            for key in c2["target"]:
                target_key = key
                if(target_key not in pairs[c2["action"]]):
                    throw_501()
                    return False              
        else:
            throw_501()
            return False
    else:
        throw_501()
        return False
    return True














# find out what action is used and execute the right function
def execute(c2):
    if(c2["action"] == "deny"):
       if(deny_exe(c2)):
            throw_200()
    elif (c2["action"] == "contain"):
       if(contain_exe(c2)):
            throw_200()
    elif(c2["action"] == "query"):
       query_exe(c2)          
    elif(c2["action"] == "delete"):
        if(delete_exe(c2)):
            throw_200()
    elif(c2["action"] == "detonate"):
        throw_501() #this action will not be implemented but is fitting for the type of profile we have  




#region proxies
def deny_exe(c2):
    if(c2["target"] == "email_addr"):
        throw_200() # blocking email address should be done on the mail server of the company or on the clients side in outlook etc.

    # adds ipv4 rule
    elif("ipv4_net" in c2["target"]):
        if(validateIPv4(c2["target"]["ipv4_net"])):
            ipAddrCIDR = c2["target"]["ipv4_net"]
            try:
                # run sudo block range
                block_command = ['sudo', 'iptables', '-A', 'INPUT', '-s', ipAddrCIDR , '-j', 'DROP']
                subprocess.Popen(block_command)
                
                block_command = ['sudo', 'iptables', '-A', 'OUTPUT', '-s', ipAddrCIDR , '-j', 'DROP']
                subprocess.Popen(block_command)

                # save sudo
                save_command = 'sudo bash -c "iptables-save>/etc/iptables/rules.v4"'
                os.system(save_command)

            except:
                throw_500()
    
    
    elif("ipv6_net" in c2["target"]):
        if(validateIPv6(c2["target"]["ipv6_net"])):
            ipAddrCIDR = c2["target"]["ipv6_net"]
            try:
                # run sudo block range
                block_command = ['sudo', 'ip6tables', '-A', 'INPUT', '-s', ipAddrCIDR , '-j', 'DROP']
                subprocess.Popen(block_command)
                block_command = ['sudo', 'ip6tables', '-A', 'OUTPUT', '-s', ipAddrCIDR , '-j', 'DROP']
                subprocess.Popen(block_command)
                # save sudo
                save_command = 'sudo bash -c "ip6tables-save>/etc/iptables/rules.v6"'
                os.system(save_command)

            except:
                throw_500()
    elif("mac_addr" in c2["target"]):
        macAddr = c2["target"]["mac_addr"]
        try:
            # run sudo block range
            block_command_proto = 'sudo iptables -A INPUT -m mac --mac-source '+str(macAddr) + ' -j DROP'
            block_command = block_command_proto.split()
            subprocess.Popen(block_command)
            subprocess.Popen(block_command)
            # save sudo
            save_command = 'sudo bash -c "iptables-save>/etc/iptables-rules"'
            os.system(save_command)

        except:      
            throw_500()
            return False
    else:      
        throw_501()
        return False
    return True



# removes sudo rights of user and deactivates network card
def contain_exe(c2):
    # check if the mac_addr in the JSON is the same as ours     
    if("mac_addr" in c2["target"]):
        macAddr = returnMac()
        fillerMac = c2["target"]["mac_addr"]
        if(c2["target"]["mac_addr"] == fillerMac):
            netName = returnNetName()
            if(netName):
                # Problem: No Response can be sent back because network card is down
                # Getting not response will atleast ensure that the network card was deactivated
                # testing shows our method works
         
                # BLOCKS ALL TRAFFIC

                cmd = ("chmod +x /home/"+user+"/Desktop/restart.sh").split()
                subprocess.Popen(cmd)
                cmd = ("sudo iptables -P INPUT DROP").split()
                subprocess.Popen(cmd)
                cmd = ("sudo iptables -P OUTPUT DROP").split()
                subprocess.Popen(cmd)
                save_command = 'sudo bash -c "iptables-save>/etc/iptables/rules.v4"'
                os.system(save_command)
                cmd = ("sudo ip6tables -P INPUT DROP").split()
                subprocess.Popen(cmd)
                cmd = ("sudo ip6tables -P OUTPUT DROP").split()
                subprocess.Popen(cmd)
                save_command = 'sudo bash -c "ip6tables-save>/etc/iptables/rules.v6"'
                os.system(save_command)

                cmd = ('sudo ip link set '+netName+' down').split()
                throw_200()
                subprocess.Popen(cmd)   

                # REMOVES USER FROM SUDO AND REMOVES NO PASSWD:
                ## careful running in testing, removes rights
                os.system("sudo shutdown -r +1")
                cmd = ("sudo deluser "+user+" sudo").split()
                subprocess.Popen(cmd)
                ## removes the last line from visudo, that line is the NOPASSWD: line we added for easier testing
                cmd = '/home/'+user+'/Desktop/removePW.sh'
                subprocess.call(['sh',cmd]) 
                      
            else:
                throw_500()
                return False
        
    else:
        throw_501()
        return False

    throw_500()
    return False

# return versions etc of the normal query command
# only returns the specified things
def query_exe(c2):
    keys = list()
    response = {"status": 200, "status_text": "OK","results": dict()}
    for key in c2["target"]:
        keys.append(str(key))
    for key in keys:
        if(key != "features"):
            throw_501()
            return False
        else:
            exp_results = list()
            for res_key in c2["target"][key]:
                exp_results.append(res_key)
            for res_key in exp_results:
                if(res_key == "versions"): # rate_limit will be a set value
                    ver_list = list()
                    ver_list.append("1.0")
                    version = {"versions": ver_list}
                    response["results"].update(version)
                elif(res_key == "profiles"):
                    prof_list = list()
                    prof_list.append("usp")
                    profiles = {"profile": prof_list}
                    response["results"].update(profiles)
                    pass
                elif(res_key == "rate_limit"):
                    rate_limits = {"rate_limit": 100}
                    response["results"].update(rate_limits)
                elif(res_key == "pairs"):
                    deny_P = {"deny": ["ipv4_net","ipv6_net","mac_addr","email_addr"]}
                    contain_P = {"contain": ["mac_addr"]}
                    query_P = {"query": ["features"]}
                    delete_P = {"delete": ["file"]}
                    detonate_P = {"detonate": ["file"]}
                    pairs = {"pairs": dict()}
                    pairs["pairs"].update(deny_P)
                    pairs["pairs"].update(contain_P)
                    pairs["pairs"].update(query_P)
                    pairs["pairs"].update(delete_P)
                    pairs["pairs"].update(detonate_P)
                    response["results"].update(pairs)
    print(json.dumps(response))
    return True

# deletes the file that is in that path, path has to be fully given
def delete_exe(c2):
    if("file" in c2["target"]):
        if("path" in c2["target"]["file"]):
            try:
                cmd = ('sudo rm '+ c2["target"]["file"]["path"])
                if cmd is not None:
                    os.system(cmd)                   
                else:
                    throw_500()
                    return False                
            except:
                throw_500()            
        else:
            throw_501()
            return False
    else:
        throw_501()
        return False
    return True
#endregion


#----------------------------------------------------------------------------------------------------
#region status_codes

# throws the status codes if either a exception was thrown
# or if the command is not supported by our actuator profile
# 200 thrown when everything worked
def throw_200():
    response = {"status": 200, "status_test": "OK"}
    print(str(json.dumps(response)))


def throw_501():
    response = {"status": 501, "status_test": "Not Implemented"}
    print(json.dumps(response))


def throw_500():
    response = {"status": 500, "status_test": "Internal Server Error"}
    print(json.dumps(response))

#endregion

# calls main function
# time function for testing the time the contain function needs to finish
start_time = time.time()
watchdog()
with open(locLog,"a") as infile:
    infile.write("\n")
    infile.write(str(time.time()-start_time))

