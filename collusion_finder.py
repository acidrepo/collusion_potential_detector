import logging
import logging.config
from optparse import OptionParser
import os
from sets import Set
import collusion
from facts import generate_facts
from prolog import collusion_sets

__author__ = 'jorgeblasco'


def main():
    parser = OptionParser(usage="usage: The program receives two arguments: (1) folder with the APK files to analyse as argument. (2) file with the collusion rules ")
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=True,
                  help="make lots of noise [default]")
    parser.add_option("-s", "--storage",
                  action="store_true", dest="storage", default=None,
                  help="Adds rules to consider external storage as a possible communication channel")
    parser.add_option("-f", "--filter",
                  action="store", dest="filter", default="",
                  help="Folder with intents to filter out from the fact list")
    parser.add_option("-l", "--length",
                  action="store", dest="length", default=0,
                  help="look for communication paths of length l")
    (options, args) = parser.parse_args()
    if len(args)!=2:
        parser.error("Incorrect number of arguments. You must input the folder where APK files to be analysed are stored and the collusion rule file")
    if options.verbose:
        LOG_CONFIG = {'version':1,
              'root':{'level':'INFO'}
                }
        logging.config.dictConfig(LOG_CONFIG)
    app_foler = args[0]
    collusion_rules = args[1]
    result_prefix = "temp"
    logging.info("Generating Facts")
    prolog_file = generate_facts(app_foler,result_prefix,rules=collusion_rules,storage=options.storage)
    logging.info("Facts generated in temp files")
    c_sets = Set()
    for collusion_kind in collusion.colluding_predicates:
        logging.info("Getting colluding sets for %s",collusion_kind)
        if options.length == 0:
            c_sets = c_sets.union(collusion_sets(prolog_file,collusion_kind,filter_folder=options.filter,length=0,app=""))
        else:
            for i in range(2,options.length):
                c_sets = c_sets.union(collusion_sets(prolog_file,collusion_kind,filter_folder=options.filter,length=i,app=""))
    print "COLLUSION RESULTS"
    print "*****************"
    print "*****************"
    print str(len(list(c_sets)))+" suspicious collusion sets found"
    for c_set in list(c_sets):
        c_set.description()
    logging.info("++ EXECUTION FINISHED ++")
    os.remove("temp_packages.txt")
    os.remove("temp_uses.txt")
    os.remove("temp_trans.txt")
    os.remove("temp_recv.txt")


if __name__ == "__main__":
    main()
