from logging import Logger
import logging
from acid_detectors.utils import track_string_value, get_instruction_offset, get_path_of_method


class SharedPreferencesAnalysis(object):

    def __init__(self,package,preference_file, operation):
        self.package = package
        self.preference_file = preference_file
        self.operation = operation

def get_shared_preferences_writes(apk,d,dx,include_support=None):
    shared_preferences = []
    sharedprefs_instruction_paths = dx.tainted_packages.search_methods(".", "getSharedPreferences", ".")
    context_instruction_paths = dx.tainted_packages.search_methods(".", "createPackageContext", ".")
    for path in sharedprefs_instruction_paths:
        src_class_name, src_method_name, src_descriptor =  path.get_src(d.get_class_manager())
        method = d.get_method_by_idx(path.src_idx)
        i = method.get_instruction(0,path.idx)
        index = get_instruction_offset(i,method)
        if is_edit_present_later(method,index):
            new_var = ""
            if i.get_op_value() == 0x6E:
                new_var = i.get_output().split(",")[1].strip()
            elif i.get_op_value() == 0x74:
                new_var = i.get_output().split(",")[0].split(".")[-1].strip()[1:]
                num = int(new_var)-1
                new_var = "v"+`num`
            pref_file = track_string_value(method,index-1,new_var)
            if not src_method_name  in [p.get_src(d.get_class_manager())[1] for p in context_instruction_paths]:
                package = apk.get_package()
            else:
                context_path = get_path_of_method(src_class_name,src_method_name, context_instruction_paths,d)
                context_method = d.get_method_by_idx(context_path.src_idx)
                c_i = context_method.get_instruction(0,context_path.idx)
                c_index = get_instruction_offset(c_i,context_method)
                c_name_var = c_i.get_output().split(",")[1].strip()
                package = track_string_value(context_method, c_index-1, c_name_var)
            sharedprefs = SharedPreferencesAnalysis(package, pref_file,"write")
            shared_preferences.append(sharedprefs)
    return shared_preferences


def get_shared_preferences_reads(apk,d,dx,include_support=None):
    shared_preferences = []
    sharedprefs_instruction_paths = dx.tainted_packages.search_methods(".", "getSharedPreferences", ".")
    context_instruction_paths = dx.tainted_packages.search_methods(".", "createPackageContext", ".")
    for path in sharedprefs_instruction_paths:
        src_class_name, src_method_name, src_descriptor =  path.get_src(d.get_class_manager())
        logging.info("Standard Path :"+src_class_name+" method="+src_method_name)
        method = d.get_method_by_idx(path.src_idx)
        i = method.get_instruction(0,path.idx)
        index = get_instruction_offset(i,method)
        logging.info("index is "+str(index))
        new_var = ""
        if i.get_op_value() == 0x6E:
            new_var = i.get_output().split(",")[1].strip()
        elif i.get_op_value() == 0x74:
            new_var = i.get_output().split(",")[0].split(".")[-1].strip()[1:]
            num = int(new_var)-1
            new_var = "v"+`num`
        # we look the position of the method in
        pref_file = track_string_value(method, index-1, new_var)
        if not src_method_name  in [p.get_src(d.get_class_manager())[1] for p in context_instruction_paths]:
            package = apk.get_package()
        else:
            context_path = get_path_of_method(src_class_name,src_method_name, context_instruction_paths,d)
            context_method = d.get_method_by_idx(context_path.src_idx)
            c_i = context_method.get_instruction(0,context_path.idx)
            c_index = get_instruction_offset(c_i,context_method)
            c_name_var = c_i.get_output().split(",")[1].strip()
            package = track_string_value(context_method, c_index-1, c_name_var)
        sharedprefs = SharedPreferencesAnalysis(package, pref_file,"read")
        shared_preferences.append(sharedprefs)
    return shared_preferences

def is_edit_present_later(method,index):
    present = None
    try:
        while index < method.get_length():
            ins = method.get_instruction(index)
            if("android/content/SharedPreferences;->edit()" in ins.get_output()):
                return True
            index = index + 1
    except IndexError:
        #Fail gently. beginning of the array reached
        return None
    return None

def tainted_is_create_package_context_present(d, dx, method,class_name="."):
    z = dx.tainted_packages.search_methods(class_name, "createPackageContext", ".")
    if len(z)==0:
        return None
    else:
        for path in z:
            m = d.get_method_by_idx(path.src_idx)
            if m == method:
                return True

def track_get_shared_preferences_direct(method,index,variable):
    action = ""
    ins = method.get_instruction(index)
    if ins.get_op_value() in [0x0C]:
        variable = ins.get_output().split(",")[0].strip()
        index += 1
    try:
        while index < method.get_length():
            ins = method.get_instruction(index)
            if variable in ins.get_output() and "getSharedPreferences" in ins.get_output():
                new_var = ins.get_output().split(",")[1].strip()
                action = track_string_value(method, index-1, new_var)
                return action
            elif variable in ins.get_output().split(",")[1].strip() and ins.get_op_value() in [0x07, 0x08]:
                # Move operation, we just need to track the new variable now.
                variable = ins.get_output().split(",")[0].strip()
            index += 1
    except IndexError:
        return action
    return action