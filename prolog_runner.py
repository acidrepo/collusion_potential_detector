from collusion import find_all_colluding, communication_channel, CollusionSet

__author__ = 'jorgeblasco'
import logging
from optparse import OptionParser



def run_prolog_program(prolog_file,collusion_kind,filter_folder=""):
    app_sets_list = find_all_colluding(collusion_kind,prolog_file)
    for app_set in app_sets_list:
        channels = communication_channel(app_set,prolog_file)
        c_set = CollusionSet(app_set,channels)
        c_set.short_description()


def main():
    usage = "usage: %prog arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=True,
                  help="make lots of noise [default]")
    (options, args) = parser.parse_args()
    if options.verbose:
        logger.setLevel(logging.INFO)
    if len(args) == 2:
        run_prolog_program(args[0], args[1])
    else:
        parser.error("Use two arguments. 1- prolog file, 2 - collusion kind")

if __name__ == "__main__":
    logging.basicConfig()
    logger = logging.getLogger(__name__)
    main()