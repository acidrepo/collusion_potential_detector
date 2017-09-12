import fnmatch
import ntpath
import sys
import os
sys.path.append("androguard-acid/")
sys.path.append("../androguard-acid/")
import androguard.core.bytecodes.dvm as dvm

__author__ = 'jorgeblasco'


def should_analyze(class_name,include_support=None):
    if include_support:
        return True
    elif 'Landroid/support' in class_name:
        return None
    elif 'Ljavassist' in class_name:
        return None
    elif 'Lcom/google/android' in class_name:
        return None
    else:
        return True

def track_method_call_action(method, index, intent_variable):
    action = ""
    while index > 0:
        ins = method.get_instruction(index)
        #print "1---"+ins.get_name()+" "+ins.get_output()
        if (intent_variable in ins.get_output() and ins.get_op_value() in [12] ):#12 is move-result-object
            ins2 = method.get_instruction(index-1)
            #print "2---"+ins2.get_name()+" "+ins.get_output()
            if len(ins2.get_output().split(","))==2:
                action = ins2.get_output().split(",")[1] + action
            elif len(ins2.get_output().split(","))==3 and intent_variable == ins2.get_output().split(",")[0]:
                action = ins2.get_output().split(",")[2] + action
        elif intent_variable in ins.get_output() and ins.get_name()=="new-instance":
            index = 0
            action = ins.get_output().split(",")[1] + action
        index -= 1
    return action

def get_path_of_method(class_name,method_name, path_list,d):
    for p in path_list:
        src_class_name, src_method_name, src_descriptor =  p.get_src(d.get_class_manager())
        if src_method_name == method_name and src_class_name == class_name:
            return p
    return None

def is_path_of_method_in_package(class_name,method_name, path_list,d):
    for p in path_list:
        src_class_name, src_method_name, src_descriptor =  p.get_src(d.get_class_manager())
        package = ntpath.dirname(src_class_name)
        if (src_method_name == method_name and src_class_name == class_name) or package in class_name:
            return p
    return None

def get_instruction_offset(instruction,method):
    for index,i in enumerate(method.get_instructions()):
        if i.get_raw() == instruction.get_raw():
            return index
    return -1


def track_string_value(method,index,variable):
    """
        Tracks back the value of a string variable that has been declared in code
        If the value comes from a literal string, it returns it.
        If the valua cannot be traced back to a literal string, it returns the chain
        of method calls that resulted in that string until initialization of the object
    :param method: is the method where we are searching
    :param index: is the next instruction after the declaration of the IntentFilter has been found
    :param variable: is the register name where the IntentFilter is placed
    :return:
    """
    action = "NotTracedBackPossibleParameter"
    while index >= 0:
        ins = method.get_instruction(index)
        if variable == ins.get_output().split(",")[0].strip() and ins.get_op_value() in [0x1A,0x1B]:#0x1A is const-string or const-string/jumbo
            action = ins.get_output().split(",")[1].strip()
            return action[1:-1]
        elif variable == ins.get_output().strip() and ins.get_op_value() in [12]:#12 is move-result-object
            ins2 = method.get_instruction(index-1)
            if len(ins2.get_output().split(","))==2:
                action = ins2.get_output().split(",")[1] + action
            elif len(ins2.get_output().split(","))==3 and variable == ins2.get_output().split(",")[0]:
                action = ins2.get_output().split(",")[2] + action
        elif variable in ins.get_output() and ins.get_name()=="new-instance":
            # The register might being reused in another variable after this instruction
            # Stop here
            index = -1
            action = ins.get_output().split(",")[1] + action
        elif variable == ins.get_output().split(",")[0].strip() and ins.get_op_value() in [0x07, 0x08]:
            # Move operation, we just need to track the new variable now.
            variable = ins.get_output().split(",")[1].strip()
        elif variable == ins.get_output().split(",")[0].strip() and ins.get_op_value() in [0x54]:#taking value from a field call.
            action = ins.get_output().split(",")[2].strip()
            index = -1
        elif variable == ins.get_output().split(",")[0].strip() and ins.get_op_value() in [0x62]:#sget-object
            action = ins.get_output().split(",")[1].strip()#Get the variable name
            index = -1
        index -= 1
    return action


def track_int_value(method,index,variable):
    """
        Tracks back the value of an int variable that has been declared in code
       If the value cannot be traced back to an integer, it returns the chain
        of method calls that resulted in that string until initialization of the object
    :param method: is the method where we are searching
    :param index: is the next instruction index where to start looking backwards
    :param variable: is the register name where the int value is placed
    :return:
    """
    int_value = -1
    while index >= 0:
        ins = method.get_instruction(index)
        if variable == ins.get_output().split(",")[0].strip() and ins.get_op_value() in [0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19]:#const instructions
            if isinstance(ins,dvm.Instruction11n):
                return int(ins.B)
            elif isinstance(ins,dvm.Instruction21s):
                return int(ins.BBBB)
            elif isinstance(ins,dvm.Instruction31i):
                return int(ins.BBBBBBBB)
            else:
                print "Not controlled"
                return 0
        elif variable == ins.get_output().split(",")[0].strip() and ins.get_op_value() in [0x52, 0x53] and ins.get_output().split(" ") == "I":#taking value from a field
            int_value = ins.get_output().split(",")[2].strip()
            instance_name = ins.get_output().split(",")[2].strip()
            int_value = look_for_sput_of_int_instance(method,instance_name)
            return int(int_value)
            index = -1
        index -= 1
    return int_value

def look_for_sput_of_int_instance(method, instance_name):
    for m in method.CM.vm.get_methods():
        for index,i in enumerate(m.get_instructions()):
            if i.get_op_value() in [0x67,68] and instance_name in i.get_output():
                string_var = i.get_output().split(",")[0].strip()
                return track_int_value(m,index,string_var)
    return instance_name

def look_for_put_of_string_instance(method, instance_name):
    for m in method.CM.vm.get_methods():
        for index,i in enumerate(m.get_instructions()):
            if i.get_op_value() in [0x5B] and instance_name in i.get_output():
                string_var = i.get_output().split(",")[0].strip()
                return track_string_value(m,index,string_var)
    return instance_name

def get_all_in_dir(folder,extension):
    matches = []
    for root, dirnames, filenames in os.walk(folder):
        for filename in fnmatch.filter(filenames, '*'+extension):
            if ".DS_Store" not in filename:
                matches.append(os.path.join(root, filename))
    return matches

def escape_quotes(string=""):
    return string.replace("\'",'\\\'')


def is_contained_in_strings_of_list(string,list):
    for element in list:
        if element in string:
            return True
    return None

def remove_duplicate_lines(infilename,outfilename,remove_infile=True):
    lines_seen = set() # holds lines already seen
    outfile = open(outfilename, "a")
    for line in open(infilename, "r"):
        if line not in lines_seen: # not a duplicate
            outfile.write(line)
            lines_seen.add(line)
    outfile.close()
    if remove_infile:
        os.remove(infilename)
    return True

def stats_file(infilename,statsfilename):
    channels = {}
    for line in open(infilename, "r"):
        channel = line.split(",")[1][1:-4]
        if channels.has_key(channel):
            channels[channel]+=1
        else:
            channels[channel]=1
    with open(statsfilename,'w') as out:
        for key in channels.keys():
            out.write("{0},{1}\n".format(key,channels[key]))
    return statsfilename

def swipl_path():
    if os.name == 'posix':
        return 'swipl'
    else:
        return 'swipl'

