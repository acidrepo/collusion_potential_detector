import logging
import re
from acid_detectors.implicit_intents import get_implicit_intents, get_dynamic_receivers, get_static_receivers
from acid_detectors.shared_preferences import get_shared_preferences_writes, get_shared_preferences_reads
from optparse import OptionParser
from sets import Set
import sys
import os
import traceback
import fnmatch
sys.path.append("androguard-acid/")
from androguard.misc import AnalyzeAPK
from androguard.core.androconf import CONF
from androguard.session import Session
import ntpath
from acid_detectors.utils import  escape_quotes

__author__ = 'jorgeblasco'



def generate_prolog_facts(app_folder,result_prefix):
    files = get_all_in_dir(app_folder,"*")
    for file in files:
        logger.info("Analyzing file %s",file)
        try:
            a,d, dx = AnalyzeAPK(file)
            # Create package to file relations
            with open(result_prefix+"_packages.txt", 'a') as f:
                f.write("package('"+a.get_package()+"','"+ntpath.basename(file)+"').\n")
            # Permissions
            permissions = []
            permissions.extend([(str(a.get_package()), permission) for permission in a.get_permissions()])
            with open(result_prefix+"_uses.txt", 'a') as f:
                for permission in permissions:
                    f.write("uses('"+permission[0]+"','"+permission[1]+"').\n")
            # Intents
            logger.info("Looking for Intent Sends")
            sends = Set()
            sends.update([(str(a.get_package()),"i_"+intent.action) for intent in get_implicit_intents(a,d,dx)])
            # Shared Prefs
            logger.info("Looking for Shared Prefs Sends")
            sends.update([(str(a.get_package()),"sp_"+shared.package+"_"+shared.preference_file) for shared in get_shared_preferences_writes(a,d,dx)])
            with open(result_prefix+"_trans.txt", 'a') as f:
                for send in sends:
                    f.write("trans('"+send[0]+"','"+escape_quotes(send[1])+"').\n")
            # Receivers
            logger.info("Looking for Dynamic Receivers")
            receives = Set()
            receives.update([(str(a.get_package()),"i_"+receiver.get_action()) for receiver in get_dynamic_receivers(a,d,dx)])
            logger.info("Looking for Static Receivers")
            receives.update([(str(a.get_package()),"i_"+receiver.get_action()) for receiver in get_static_receivers(a)])
            # Shared Prefs
            logger.info("Looking for Shared Prefs Receives")
            receives.update([(str(a.get_package()),"sp_"+shared.package+"_"+shared.preference_file) for shared in get_shared_preferences_reads(a,d,dx)])
            with open(result_prefix+"_recv.txt", 'a') as f:
                 for receive in receives:
                    f.write("recv('"+receive[0]+"','"+escape_quotes(receive[1])+"').\n")
        except:
            print "--Error with file "+file
            traceback.print_exc()
    logger.info("Results saved in %s files",result_prefix)


def main():
    usage = "usage: %prog arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=True,
                  help="make lots of noise [default]")
    (options, args) = parser.parse_args()
    if len(args)!=2:
        parser.error("incorrect number of arguments")
    if options.verbose:
        logger.setLevel(logging.INFO)
    generate_prolog_facts(args[0],args[1])

if __name__ == "__main__":
    logging.basicConfig()
    logger = logging.getLogger(__name__)
    main()
