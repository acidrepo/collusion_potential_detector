import logging
from sets import Set
from acid_detectors.utils import get_all_in_dir, swipl_path

__author__ = 'jorgeblasco'
import re
import os.path
import ast
from subprocess import check_output
#swipl -q  -t 'findall(P,colluding_info(A,B,P),Ps),writeln(Ps),true' -s imps_detector.pl


channel_numbering_suffix = ".numbered_channels"
channel_numbering_mapping_suffix = ".mapping_channels"
package_numbering_suffix = ".numbered_packages"
package_numbering_mapping_suffix = ".mapping_packages"


class CollusionSet:

    def __init__(self,kind,app_list,channels_lists,mapping_packages=None,mapping_channels=None):
        self.kind = kind
        self.app_list = app_list
        if mapping_packages:
            self.app_list = [mapping_packages[int(app)] for app in app_list]
        if mapping_channels:
            self.channels_lists = []
            for channels in channels_lists:
                self.channels_lists.append([mapping_channels[int(channel)] for channel in channels])
        else:
            self.channels_lists = channels_lists


    def __str__(self):
        if len(self.app_list)==0:
            return ""
        else:
            result = self.kind+"\n"+self.app_list[0]
            for channels in self.channels_lists:
                for i in range(0,len(self.channels),1):
                    result = result +"-->" + self.channels[i]+ "-->"+ self.app_list[i+1]
            return result

    def short_description(self):
        print str(self)

    def description(self):
        print "+++++++++++++++"
        print " Colluding Set"
        print "+++++++++++++++"
        print self.kind
        print "--------------"
        print self.app_list
        print "-- Channels --"
        for channels in self.channels_lists:
            print channels


colluding_predicates = ['colluding_info', 'colluding_money1','colluding_money2','colluding_service','colluding_camera','colluding_accounts','colluding_sms']


def find_all_comm_setof(rule_file):
    #Extract package names
    packages = find_packages()
    #Execute setof over each package name
    comm_list = []
    for package in packages:
        comm_list.extend(find_all_comm_package(rule_file,package))
    return comm_list


def find_packages(rule_file):
    packages = Set()
    count = 0
    with open(rule_file) as infile:
        for line in infile:
            if line.startswith("recv") or line.startswith("trans") or line.startswith("uses") or line.startswith("package"):
                item = line.split(",")[0].split("(")[1]
                packages.add(item)
    return packages


def find_comm_length_all(rule_file,length=2):
    return find_comm_length_package(rule_file,"AppA",length)

def find_comm_length_package(rule_file,package_name="AppA",length=2):
    if not os.path.isfile(rule_file) :
        return None
    logging.info("Finding communications with "+str(package_name))
    call = [swipl_path(),'-G4g', '-q', '-g', "( \+ comm_length({0},AppB,{1},Visited,Path) -> Ps = [] ; setof(({0},AppB,Path),Visited^comm_length({0},AppB,{1},Visited,Path),Ps)),writeln(Ps),halt".format(package_name,length), "-t", "'halt(1)'", '-s', rule_file]
    result = check_output(call)
    return parse_returned_app_list(result)

def find_all_comm_package(rule_file,package_name):
    if not os.path.isfile(rule_file) :
        return None
    logging.info("Finding communications with "+package_name)
    call = [swipl_path(),'-G4g', '-q', '-g', "( \+ comm({0},AppB,Visited,Path,Length) -> Ps = [] ; setof(({0},AppB,Path),Visited^Length^comm({0},AppB,Visited,Path,Length),Ps)),writeln(Ps),halt".format(package_name), "-t", "'halt(1)'", '-s', rule_file]
    result = check_output(call)
    return parse_returned_app_list(result)

def find_all_comm(rule_file):
    if not os.path.isfile(rule_file) :
        return None
    logging.info("Executing SWIPL command")
    call = [swipl_path(),'-G4g', '-q', '-g', "( \+ comm({0},AppB,Visited,Path,Length) -> Ps = [] ; setof((AppA,AppB,Path),Visited^Length^comm(AppA,AppB,Visited,Path,Length),Ps)),writeln(Ps),halt","-t","'halt(1)'", '-s', rule_file]
    result = check_output(call)
    return parse_returned_app_list(result)

def find_all_colluding(rule_file,colluding_predicate):
    return find_package_colluding(rule_file,"AppA",colluding_predicate)

def find_package_colluding(rule_file,package,colluding_predicate):
    if colluding_predicate not in colluding_predicates:
        return None
    if not os.path.isfile(rule_file) :
        return None
    logging.info("Executing SWIPL command")
    call = [swipl_path(),'-G4g', '-q', '-g', "( \+ {0}({1},AppB,Path) -> Ps = [] ; setof(({1},AppB,Path),{0}({1},AppB,Path),Ps)),writeln(Ps),halt".format(colluding_predicate,package),"-t","'halt(1)'", '-s', rule_file]
    result = check_output(call)
    return parse_returned_app_list(result)

def find_all_colluding_length(rule_file,colluding_predicate,length=2):
    return find_package_colluding_length(rule_file,colluding_predicate,"AppA",length)

def find_package_colluding_length(rule_file,colluding_predicate,package="AppA",length=2):
    if colluding_predicate not in colluding_predicates:
        return None
    if not os.path.isfile(rule_file) :
        return None
    colluding_predicate = colluding_predicate+"_length"
    logging.info("Executing SWIPL command")
    call = [swipl_path(),'-G4g', '-q', '-g', "( \+ {0}({2},AppB,Path,{1}) -> Ps = [] ; setof(({2},AppB,Path),{0}({2},AppB,Path,{1}),Ps)),writeln(Ps),halt".format(colluding_predicate,length,package),"-t","'halt(1)'", '-s', rule_file]
    logging.debug("Call is :"+str(call))
    result = check_output(call)
    logging.info("Ids of apps obtained :"+result)
    return parse_returned_app_list(result)

#channel(AppA,AppB,Path,Channel)
# 423,420,[55,426]
def communication_channels(rule_file,app_set):
    if len(app_set) < 2:
        return []
    app_a = app_set[0]
    app_b = app_set[-1]
    path_string = "[]"
    if len(app_set) > 2:
        path_string = ",".join([str(i) for i in app_set[1:-1]])
        path_string = "[" + path_string+ "]"
    prolog_command = 'setof(C,channel({0},{1},{2},C),Cs),writeln(Cs),halt'.format(app_a,app_b,path_string)
    logging.debug("Executing :"+prolog_command)
    call = [swipl_path(),'-G4g','-q', "-g", prolog_command, "-t","'halt(1)'", "-s", rule_file]
    result = check_output(call)
    return parse_returned_channel_list(result)


def parse_returned_channel_list(list_string):
    result = list_string.replace("|",",")
    p = re.compile("\[([\d, \|]*)\]")
    channel_list = []
    for (channels) in re.findall(p,result):
        channel_list.append(ast.literal_eval("["+channels+"]"))
    return channel_list


def parse_returned_app_list(list_string):
    result = list_string.replace("|",",")
    p = re.compile(ur'\(([0-9]*),([0-9]*),\[([a-zA-Z\d\.\[,_]*)\]')
    colluding_appset_list = []
    for (a,b,path) in re.findall(p, result):
        comm_apps_list = []
        comm_apps_list.append(int(a))
        path_list = ast.literal_eval("["+path+"]")
        comm_apps_list.extend(path_list)
        comm_apps_list.append(int(b))
        colluding_appset_list.append(comm_apps_list)
    return colluding_appset_list

def read_mapping_file(mapping_file):
    mapping = []
    with open(mapping_file,'r') as r:
        for line in r:
            values = line.split(":")
            if len(values) == 2:
                mapping.append(values[0])
    return mapping

def filter_intents_by_folder(rule_file,intent_filters_folder):
    files = get_all_in_dir(intent_filters_folder,"*")
    lines_to_remove = []
    filtered_file = rule_file+".filtered"
    for file in files:
        with open(file,'r') as r:
            lines_to_remove.extend([line[:-1] for line in r.readlines()])
    with open(filtered_file,'w') as f, open(rule_file,'r') as rulef:
        rule_lines = rulef.readlines()
        final_lines = [rule for rule in rule_lines if len([line for line in lines_to_remove if line in rule])==0]
        f.writelines(final_lines)
    return filtered_file


def filter_intents_by_file(file,intent_filters_file):
    lines_to_remove = []
    filtered_file = file+".filtered"
    with open(intent_filters_file,'r') as r:
        lines_to_remove.extend([line[:-1] for line in r.readlines()])
    with open(filtered_file,'w') as f, open(file,'r') as rulef:
        rule_lines = rulef.readlines()
        final_lines = [rule for rule in rule_lines if len([line for line in lines_to_remove if line in rule])==0]
        f.writelines(final_lines)
    return filtered_file


def replace_channels_strings_file(in_filename):
    mapping = {}
    count = 0
    out_filename = in_filename +channel_numbering_suffix
    with open(in_filename) as infile, open(in_filename+channel_numbering_mapping_suffix, 'w') as mapping_file, open(out_filename,"w") as outfile:
        for line in infile:
            if line.startswith("recv") or line.startswith("trans"):
                item = line[line.index(",")+1:-3]
                if not mapping.has_key(item):
                    mapping_file.write(item+":"+str(count)+"\n")
                    mapping[item] = count
                    count += 1
                line = line.replace(item,str(mapping[item]))
            outfile.write(line)
    return out_filename


def replace_packages_strings_file(in_filename):
    mapping = {}
    count = 0
    out_filename = in_filename +package_numbering_suffix
    with open(in_filename) as infile, open(in_filename+package_numbering_mapping_suffix, 'w') as mapping_file, open(out_filename,"w") as outfile:
        for line in infile:
            if line.startswith("recv") or line.startswith("trans") or line.startswith("uses") or line.startswith("package"):
                item = line.split(",")[0].split("(")[1]
                if not mapping.has_key(item):
                    mapping_file.write(item+":"+str(count)+"\n")
                    mapping[item] = count
                    count += 1
                line = line.replace(item,str(mapping[item]))
            outfile.write(line)
    return out_filename


