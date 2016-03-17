from logging import Logger
import logging
from acid_detectors.utils import track_string_value, get_instruction_offset, get_path_of_method, should_analyze, track_int_value


class SharedPreferencesAnalysis(object):

    def __init__(self,package,preference_file, operation):
        self.package = package
        self.preference_file = preference_file
        self.operation = operation

def get_shared_preferences_writes(apk,d,dx,include_support=None):
    shared_preferences = []
    sharedprefs_instruction_paths = dx.tainted_packages.search_methods("", "getSharedPreferences", "\(Ljava/lang/String; I\)Landroid/content/SharedPreferences;")
    context_instruction_paths = dx.tainted_packages.search_methods(".", "createPackageContext", ".")
    for path in sharedprefs_instruction_paths:
        src_class_name, src_method_name, src_descriptor = path.get_src(d.get_class_manager())
        if should_analyze(src_class_name,include_support):
            method = d.get_method_by_idx(path.src_idx)
            i = method.get_instruction(0,path.idx)
            index = get_instruction_offset(i,method)
            if is_edit_present_later(method,index):
                new_var = ""
                if i.get_op_value() == 0x6E:#invoke-virtual { parameters }, methodtocall
                    new_var = i.get_output().split(",")[1].strip()
                    file_mode_var = i.get_output().split(",")[2].strip()
                elif i.get_op_value() == 0x74:#invoke-virtual/range {vx..vy},methodtocall
                    new_var = i.get_output().split(",")[0].split(".")[-1].strip()[1:]
                    num = int(new_var)-1
                    new_var = "v"+`num`
                    file_mode_var = "v"+new_var
                file_mode = track_int_value(method,index-1,file_mode_var)
                if file_mode != 0:#if word readable or writable
                    pref_file = track_string_value(method,index-1,new_var)
                    context_path = get_path_of_method(src_class_name,src_method_name, context_instruction_paths,d)
                    if context_path:
                        context_method = d.get_method_by_idx(context_path.src_idx)
                        c_i = context_method.get_instruction(0,context_path.idx)
                        c_index = get_instruction_offset(c_i,context_method)
                        c_name_var = c_i.get_output().split(",")[1].strip()
                        package = track_string_value(context_method, c_index-1, c_name_var)
                    else:
                        package = apk.get_package()
                    sharedprefs = SharedPreferencesAnalysis(package, pref_file,"write")
                    shared_preferences.append(sharedprefs)
    return shared_preferences


def get_shared_preferences_reads(apk,d,dx,include_support=None):
    shared_preferences = []
    sharedprefs_instruction_paths = dx.tainted_packages.search_methods(".", "getSharedPreferences", "\(Ljava/lang/String; I\)Landroid/content/SharedPreferences;")
    context_instruction_paths = dx.tainted_packages.search_methods(".", "createPackageContext", ".")
    for path in sharedprefs_instruction_paths:
        src_class_name, src_method_name, src_descriptor = path.get_src(d.get_class_manager())
        if should_analyze(src_class_name,include_support):
            method = d.get_method_by_idx(path.src_idx)
            i = method.get_instruction(0,path.idx)
            index = get_instruction_offset(i,method)
            new_var = ""
            if i.get_op_value() in [0x6E,0x6F,0x72]:#invoke-virtual { parameters }, methodtocall
                new_var = i.get_output().split(",")[1].strip()
                file_mode_var = i.get_output().split(",")[2].strip()
            elif i.get_op_value() == 0x74:#invoke-virtual/range {vx..vy},methodtocall
                new_var = i.get_output().split(",")[0].split(".")[-1].strip()[1:]
                num = int(new_var)-1
                new_var = "v"+`num`
                file_mode_var = "v"+new_var
            else:
                print "Not Controlled"
            # we look the position of the method in
            file_mode = track_int_value(method,index-1,file_mode_var)
            if file_mode != 0:
                pref_file = track_string_value(method, index-1, new_var)
                context_path = get_path_of_method(src_class_name,src_method_name, context_instruction_paths,d)
                if context_path:
                    context_method = d.get_method_by_idx(context_path.src_idx)
                    c_i = context_method.get_instruction(0,context_path.idx)
                    c_index = get_instruction_offset(c_i,context_method)
                    c_name_var = c_i.get_output().split(",")[1].strip()
                    package = track_string_value(context_method, c_index-1, c_name_var)
                else:
                    package = apk.get_package()
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