import logging

__author__ = 'jorgeblasco'


def should_analyze(class_name,include_support=None):
    if include_support:
        return True
    elif 'Landroid/support' in class_name:
        return None
    elif 'Ljavassist' in class_name:
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
        if variable in ins.get_output() and ins.get_op_value() in [0x1A]:#0x1A is const-string
            action = ins.get_output().split(",")[1].strip()
            return action[1:-1]
        elif variable in ins.get_output() and ins.get_op_value() in [12]:#12 is move-result-object
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
        elif variable in ins.get_output().split(",")[0].strip() and ins.get_op_value() in [0x07, 0x08]:
            # Move operation, we just need to track the new variable now.
            variable = ins.get_output().split(",")[1].strip()
        elif variable in ins.get_output().split(",")[0].strip() and ins.get_op_value() in [0x54]:#taking value from a method call.
            action = ins.get_output().split(",")[2].strip()
            instance_name = ins.get_output().split(",")[2].strip()
            action = look_for_put_of_string_instance(method,instance_name)
            index = -1
        index -= 1
    return action


def look_for_put_of_string_instance(method, instance_name):
    for m in method.CM.vm.get_methods():
        for index,i in enumerate(m.get_instructions()):
            if i.get_op_value() in [0x5B] and instance_name in i.get_output():
                string_var = i.get_output().split(",")[0].strip()
                return track_string_value(m,index,string_var)
    return instance_name
