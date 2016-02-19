from acid_detectors.utils import get_all_in_dir

__author__ = 'jorgeblasco'
import re
import os.path
import ast
from subprocess import check_output
#swipl -q  -t 'findall(P,colluding_info(A,B,P),Ps),writeln(Ps),true' -s imps_detector.pl



class CollusionSet:

    def __init__(self,kind,app_list,channels):
        self.kind = kind
        self.app_list = app_list
        self.channels = channels

    def __str__(self):
        if len(self.app_list)==0:
            return ""
        else:
            result = self.kind+"\n"+self.app_list[0]
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
        print self.channels


colluding_predicates = ['colluding_info', 'colluding_money1','colluding_money2','colluding_service']

def find_all_colluding(colluding_predicate,rule_file):
    if colluding_predicate not in colluding_predicates:
        return None
    if not os.path.isfile(rule_file) :
        return None
    call = 'swipl -q  -t \'findall(P,%s(A,B,P),Ps),writeln(Ps),true\' -s %s' % (colluding_predicate,rule_file)
    result = check_output(call, shell=True)
    result = result.replace("|",",")
    pattern = "\[([a-zA-Z\d\.,_]*)\]"
    pattern_obj = re.compile(pattern)
    colluding_appset_list = []
    for (app_list) in re.findall(pattern_obj, result):
        app_list = app_list.replace(",","\',\'")
        app_list = "['"+app_list+"']"
        colluding_appset_list.append(ast.literal_eval(app_list))
    return colluding_appset_list

#swipl -q  -t "channel(['com.acid.weatherapp','acid.com.contactmanager'|'com.acid.docviewer'],C),writeln(C),true" -s imps_detector.pl
def communication_channel(app_set,rule_file):
    app_list_string = "','".join(app_set[:-1])
    app_list_string = "['" + app_list_string + "'|'" + app_set[-1] + "']"
    call = "swipl -q  -t \"channel(%s,C),writeln(C),true\" -s %s" % (app_list_string,rule_file)
    result = check_output(call, shell=True)
    channel_list = result.replace(",","\',\'")
    channel_list = "[\'"+channel_list[1:-2]+"\']"
    return ast.literal_eval(channel_list)


def filter_intents(rule_file,intent_filters_folder):
    filtered_file = "filtered_file"
    files = get_all_in_dir(intent_filters_folder,"*")
    lines_to_remove = []
    for file in files:
        with open(file,'r') as r:
            lines_to_remove.extend([line[:-1] for line in r.readlines()])
    with open(filtered_file,'w') as f:
        with open(rule_file,'r') as rulef:
            rule_lines = rulef.readlines()
            final_lines = [rule for rule in rule_lines if len([line for line in lines_to_remove if line in rule])==0]
            f.writelines(final_lines)
    return filtered_file







