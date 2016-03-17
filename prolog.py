import os
from sets import Set
from collusion import find_all_colluding, communication_channel, CollusionSet, filter_intents

__author__ = 'jorgeblasco'
import logging
import logging.config
from optparse import OptionParser

logger = logging.getLogger(__name__)

def collusion_sets(prolog_file,collusion_kind,filter_folder=""):
    sets = Set()
    if filter_folder!="" and os.path.isdir(filter_folder):
        filtered_file = filter_intents(prolog_file,filter_folder,"filtered_file")
        prolog_file = filtered_file
    app_sets_list = find_all_colluding(collusion_kind,prolog_file)
    for app_set in app_sets_list:
        channels = communication_channel(app_set,prolog_file)
        c_set = CollusionSet(collusion_kind,app_set,channels)
        sets.add(c_set)
    return sets
    if filtered_file:
        os.remove(filtered_file)


def main():
    usage = "usage: %prog arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=True,
                  help="make lots of noise [default]")
    parser.add_option("-f", "--filter",
                  action="store", dest="filter", default="",
                  help="Folder with intents to filter out from the fact list")
    (options, args) = parser.parse_args()
    if options.verbose:
        LOG_CONFIG = {'version':1,
              'root':{'level':'INFO'}
                }
        logging.config.dictConfig(LOG_CONFIG)
    if len(args) == 2:
        c_sets = collusion_sets(args[0], args[1],options.filter)
        for set in c_sets:
            set.description()
    else:
        parser.error("Use two arguments. 1- prolog file, 2 - collusion kind")

if __name__ == "__main__":
    main()