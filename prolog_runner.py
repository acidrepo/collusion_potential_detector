import logging
from optparse import OptionParser
import re
from sets import Set
from acid_detectors.utils import get_all_in_dir, is_contained_in_strings_of_list

__author__ = 'jorgeblasco'
import sys
sys.path.append("pyswip")
from pyswip import Prolog



def run_prolog_program(rules_file,fact_files=[],filter_folder=""):
    prolog = Prolog()
    # If we are going to filter intents and other information read the filters
    to_filter = []
    if filter_folder!='':
        logger.info("Reading Filters")
        files = get_all_in_dir(filter_folder,'')
        for file in files:
            with open(file,'r') as i_f:
                to_filter.extend([line for line in i_f.read().split('\n') if line !=''])
        logger.info('%s Filters loaded',len(to_filter))
    # Load rules from file
    logger.info("Loading Rules")
    with open(rules_file,'r') as f:
        lines = [rule[:-1] for rule in removeComments(f.read()).split('\n') if rule !='']
    for line in lines:
        prolog.assertz(line)
    logger.info("Loading Facts")
    for fact_file in fact_files:
        with open(fact_file,'r') as f:
            lines = [rule[:-1] for rule in removeComments(f.read()).split('\n') if rule !='']
        # Load rules from file
        #[prolog.assertz(line) for line in lines]
        to_assert = [line for line in lines if not is_contained_in_strings_of_list(line,to_filter)]
        [prolog.assertz(line) for line in lines if not is_contained_in_strings_of_list(line,to_filter)]
    #prolog.assertz("uses('a,'android.permission.ACCESS_COARSE_LOCATION')")
    logger.info("Executing Query")
    #results = list(prolog.query("bagof(P,colluding(A,B,C),Ps)"))
    results = list(prolog.query("setof(P,colluding_info(A,B,P),Ps)"))
    col = Set()
    col.update([(result['A'], result['B']) for result in results])
    for collusion in list(col):
        print collusion
        raw_input("press to continue...")
        to_query = "setof(C,channel(['"+collusion[0]+"'|'"+collusion[1]+"'],C),Cs)"
        print to_query
        channels = list(prolog.query(to_query))
        if len(channels)>0:
            for channel in channels[0]['Cs']:
                print ",".join([c.value for c in channel])
        raw_input("press to continue...")
    logger.info("Finished Executing")


# Taken from http://stackoverflow.com/a/2319116
def removeComments(string):
    string = re.sub(re.compile("/\*.*?\*/",re.DOTALL ) ,"" ,string) # remove all occurance streamed comments (/*COMMENT */) from string
    string = re.sub(re.compile("//.*?\n" ) ,"" ,string) # remove all occurance singleline comments (//COMMENT\n ) from string
    return string


def main():
    usage = "usage: %prog "
    parser = OptionParser(usage=usage)
    parser.add_option("-r", "--rules",
                  action="store", type="string", dest="rules",
                  help="File with the collusion rules (including communication ones)")
    parser.add_option("-f", "--facts",
                  action="store", type="string", dest="facts", nargs=3,
                  help="The name of the files storing the facts about apps. One file should include permission usage and the other two communication channels")
    parser.add_option("-i", "--intent",
                  action="store", type="string", dest="intent",
                  help="The name of the folder containing files with intents to remove from the list of channels")
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=True,
                  help="make lots of noise [default]")
    (options, args) = parser.parse_args()
    if options.verbose:
        logger.setLevel(logging.INFO)
    if options.facts and options.rules and options.intent:
        run_prolog_program(options.rules,options.facts,filter_folder=options.intent)
    elif options.facts and options.rules:
        run_prolog_program(options.rules,options.facts)
    elif options.facts:
        parser.error("Using only facts will produce no output as there are no rules")
    elif options.rules:
        parser.error("Using only rules will produce no output as there are no fact to reason about")


if __name__ == "__main__":
    logging.basicConfig()
    logger = logging.getLogger(__name__)
    main()