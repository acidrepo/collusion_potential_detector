from __future__ import division
from collections import Counter
import logging
import logging.config
from sets import Set
from acid_detectors.implicit_intents import get_implicit_intents, get_dynamic_receivers, get_static_receivers
from acid_detectors.shared_preferences import get_shared_preferences_writes, get_shared_preferences_reads
from optparse import OptionParser
import sys
import os
import traceback
sys.path.append("androguard-acid/")
from androguard.misc import AnalyzeAPK
from androguard.core.androconf import CONF
from androguard.session import Session
import ntpath
from acid_detectors.utils import escape_quotes, get_all_in_dir

__author__ = 'jorgeblasco'


def generate_facts(app_folder,result_prefix,rules,storage=None):
    files = get_all_in_dir(app_folder,"*")
    send_intent_actions_stats = Counter()
    recv_intent_actions_stats = Counter()
    len_files = 0
    is_apk = None
    for file in files:
        logging.info("Analyzing file %s",file)
        try:
            a,d, dx = AnalyzeAPK(file)
            is_apk = True
            # Create package to file relations
        except:
            is_apk = None
            print "Not valid APK file:  "+file
        try:
            if is_apk:
                with open(result_prefix+"_packages.txt", 'a') as f:
                    f.write("package('"+a.get_package()+"','"+ntpath.basename(file)+"').\n")
                # Permissions
                permissions = []
                permissions.extend([(str(a.get_package()), permission) for permission in a.get_permissions()])
                with open(result_prefix+"_uses.txt", 'a') as f:
                    for permission in permissions:
                        f.write("uses('"+permission[0]+"','"+permission[1]+"').\n")
                # Intents
                logging.info("Looking for Intent Sends")
                sends = Set()
                sends.update([(str(a.get_package()),"i_"+intent.action) for intent in get_implicit_intents(a,d,dx)])
                send_intent_actions_stats.update([send[1] for send in sends])
                # Shared Prefs
                logging.info("Looking for Shared Prefs Sends")
                sends.update([(str(a.get_package()),"sp_"+shared.package+"_"+shared.preference_file) for shared in get_shared_preferences_writes(a,d,dx)])
                with open(result_prefix+"_trans.txt", 'a') as f:
                    for send in sends:
                        f.write("trans('"+send[0]+"','"+escape_quotes(send[1])+"').\n")
                # Receivers
                logging.info("Looking for Dynamic Receivers")
                receives = Set()
                receives.update([(str(a.get_package()),"i_"+receiver.get_action()) for receiver in get_dynamic_receivers(a,d,dx)])
                logging.info("Looking for Static Receivers")
                receives.update([(str(a.get_package()),"i_"+receiver.get_action()) for receiver in get_static_receivers(a)])
                recv_intent_actions_stats.update([receive[1] for receive in receives])
                # Shared Prefs
                logging.info("Looking for Shared Prefs Receives")
                receives.update([(str(a.get_package()),"sp_"+shared.package+"_"+shared.preference_file) for shared in get_shared_preferences_reads(a,d,dx)])
                with open(result_prefix+"_recv.txt", 'a') as f:
                     for receive in receives:
                        f.write("recv('"+receive[0]+"','"+escape_quotes(receive[1])+"').\n")
                len_files += 1
        except:
            print "Error during analysis:  "+file
            traceback.print_exc()
    if rules != "":
        with open(os.path.splitext(rules)[0]+"_program.pl", 'w') as f:
            #write packages
            with open(result_prefix+"_packages.txt", 'r') as to_read:
                f.writelines(to_read.readlines())
            #write uses
            with open(result_prefix+"_uses.txt", 'r') as to_read:
                f.writelines(to_read.readlines())
            #write trans
            with open(result_prefix+"_trans.txt", 'r') as to_read:
                f.writelines(to_read.readlines())
                if storage:
                    f.write("trans(A,'external_storage'):- uses(A,'android.permission.WRITE_EXTERNAL_STORAGE').\n")
            #write receives
            with open(result_prefix+"_recv.txt", 'r') as to_read:
                f.writelines(to_read.readlines())
                if storage:
                    f.write("recv(A,'external_storage'):- uses(A,'android.permission.WRITE_EXTERNAL_STORAGE').\n")
                    f.write("recv(A,'external_storage'):- uses(A,'android.permission.READ_EXTERNAL_STORAGE').\n")
            with open(rules, 'r') as to_read:
                f.writelines(to_read.readlines())
    with open(result_prefix+"_intent_send_stats",'w') as send_stats_file:
        send_stats_file.write("**** Results for send intent analysis ****\n")
        send_stats_file.write("Files analized: ")
        send_stats_file.write(str(len_files))
        send_stats_file.write("\n")
        for send_stat in send_intent_actions_stats.most_common():
            freq = send_stat[1]/len_files
            send_stats_file.write(send_stat[0]+", "+"{0:.2f}".format(round(freq,2))+", "+str(send_stat[1])+"\n")
    with open(result_prefix+"_intent_recv_stats",'w') as recv_stats_file:
        recv_stats_file.write("**** Results for send intent analysis ****\n")
        recv_stats_file.write("Files analized: ")
        recv_stats_file.write(str(len_files))
        recv_stats_file.write("\n")
        for recv_stat in recv_intent_actions_stats.most_common():
            freq = recv_stat[1]/len_files
            recv_stats_file.write(recv_stat[0]+", "+"{0:.2f}".format(round(freq,2))+", "+str(recv_stat[1])+"\n")
    logging.info("Results saved in %s files",result_prefix)
    return os.path.splitext(rules)[0]+"_program.pl"


def main():
    usage = "usage: %prog arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=True,
                  help="make lots of noise [default]")
    parser.add_option('-r', '--rules',
                      action="store", dest="rules", default="",
                      help="Specify a rules file to append the result")
    parser.add_option("-s", "--storage",
                  action="store_true", dest="storage", default=None,
                  help="Adds rules to consider external storage as a possible communication channel")
    (options, args) = parser.parse_args()
    if len(args)!=2:
        parser.error("incorrect number of arguments")
    if options.verbose:
        LOG_CONFIG = {'version':1,
              'root':{'level':'INFO'}
                }
        logging.config.dictConfig(LOG_CONFIG)
    rule_file = options.rules
    if rule_file != "":
        if not os.path.isfile(rule_file):
            parser.error("Rule file does not exists")
    generate_facts(args[0],args[1],rules=options.rules,storage=options.storage)

if __name__ == "__main__":
    main()
