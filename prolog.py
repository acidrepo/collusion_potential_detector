from __future__ import division
import os
from sets import Set
import sys
from collusion import find_all_colluding, CollusionSet, filter_intents_by_folder, \
    find_all_comm, read_mapping_file, replace_channels_strings_file, replace_packages_strings_file, \
    find_all_colluding_length, find_package_colluding_length, find_package_colluding, communication_channels
import progressbar
import collusion

__author__ = 'jorgeblasco'
import logging
import logging.config
from optparse import OptionParser



def collusion_sets(prolog_file,collusion_kind,filter_folder="",length=0,app=""):
    sets = Set()
    base_file = prolog_file
    if filter_folder!="" and os.path.isdir(filter_folder):
        print "Filtering intents"
        filtered_file_name = filter_intents_by_folder(prolog_file,filter_folder)
        base_file = filtered_file_name
    numbered_channels_file = replace_channels_strings_file(base_file)
    mapping_channels = read_mapping_file(base_file+collusion.channel_numbering_mapping_suffix)
    numbered_packages_file = replace_packages_strings_file(numbered_channels_file)
    mapping_packages = read_mapping_file(numbered_channels_file+collusion.package_numbering_mapping_suffix)
    print "Finding colluding apps"
    if length >1:
        if app != "":
            app_value = mapping_packages.index("'"+app+"'")
            logging.info("Specific length and app")
            app_sets_list = find_package_colluding_length(numbered_packages_file,collusion_kind,app_value,length)
        else:
            logging.info("Specific length ")
            app_sets_list = find_all_colluding_length(numbered_packages_file,collusion_kind,length)
    elif length >=0:
        if app != "":
            app_value = mapping_packages.index("'"+app+"'")
            logging.info("Specific app")
            app_sets_list = find_package_colluding(numbered_packages_file,app_value,collusion_kind)
        else:
            logging.info("Searching for all")
            app_sets_list = find_all_colluding(numbered_packages_file,collusion_kind)
    print "Finding communication channels"
    done = 0
    for app_set in app_sets_list:
        channels = communication_channels(numbered_packages_file,app_set)
        c_set = CollusionSet(collusion_kind,app_set,channels,mapping_packages,mapping_channels)
        sets.add(c_set)
        done += 1
        #update_profess(done,len(app_sets_list))
    return sets
    #if filtered_file:
    #    os.remove(filtered_file)
    #os.remove(escaped_file)

def update_profess(done, finish):
    sys.stdout.write('\r')
    # the exact output you're looking for:
    sys.stdout.write("[%-20s] %d%% %d out of %d" % ('='*int((done/finish)*20), int(100*(done/finish)), done, finish))
    sys.stdout.flush()


def main():
    usage = "usage: %prog arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=True,
                  help="make lots of noise [default]")
    parser.add_option("-d", "--debug",
                  action="store_true", dest="debug", default=None,
                  help="make lots of noise [default]")
    parser.add_option("-f", "--filter",
                  action="store", dest="filter", default="",
                  help="Folder with intents to filter out from the fact list")
    parser.add_option("-l", "--length",
                  action="store", dest="length", default=0,
                  help="look for communication paths of length l")
    parser.add_option("-a", "--app",
                  action="store", dest="app", default="",
                  help="look for a specific app")
    (options, args) = parser.parse_args()
    if options.debug:
        LOG_CONFIG = {'version':1,
              'root':{'level':'DEBUG'}
                }
        logging.config.dictConfig(LOG_CONFIG)
    elif options.verbose:
        LOG_CONFIG = {'version':1,
              'root':{'level':'INFO'}
                }
        logging.config.dictConfig(LOG_CONFIG)
    if len(args) == 2:
        c_sets = collusion_sets(args[0], args[1],options.filter,options.length, options.app)
        for set in c_sets:
            set.description()
    else:
        parser.error("Use two arguments. 1- prolog file, 2 - collusion kind")

if __name__ == "__main__":
    main()