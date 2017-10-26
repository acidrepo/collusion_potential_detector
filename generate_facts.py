#!/usr/bin/env python

from acid_detectors.implicit_intents import get_implicit_intents, get_dynamic_receivers, get_static_receivers
from acid_detectors.shared_preferences import get_shared_preferences_writes, get_shared_preferences_reads
from acid_detectors.utils import escape_quotes, get_all_files_in_dir
import argparse
import logging
import ntpath
import os
import sys

# ensure androguard library is imported from our modified version
sys.path.append("androguard-acid/")
import androguard.misc


__author__ = "jorgeblasco and Liam O'Reilly"
VERSION_NUMBER = "1.1"


def analyse_apk_file(apk_filename):
    logging.info("Analyzing file %s", apk_filename)

    try:
        a, d, dx = androguard.misc.AnalyzeAPK(apk_filename)
    except:
        logging.warning(apk_filename + " is not a valid APK. Skipping")
        return None

    try:
        # Perform analysis
        app_facts_dict = {}

        # Package
        package_name = a.get_package()
        app_facts_dict['package_name'] = package_name

        app_base_file_name = ntpath.basename(apk_filename)
        app_facts_dict['app_base_file_name'] = app_base_file_name

        # Permissions
        logging.info("Looking for permissions")
        permission_facts = set()
        for permission in a.get_permissions():
            permission_facts.add(permission)
        app_facts_dict['permissions'] = permission_facts

        # Intent sends
        logging.info("Looking for intent sends")
        send_intent_facts = set()
        for intent in get_implicit_intents(a, d, dx):
            send_intent_facts.add(escape_quotes("i_" + intent.action))
        app_facts_dict['send_intents'] = send_intent_facts

        # Shared Prefs sends
        logging.info("Looking for shared preferences sends")
        send_shared_prefs_facts = set()
        for shared_pref in get_shared_preferences_writes(a, d, dx):
            send_shared_prefs_facts.add("sp_" + shared_pref.package + "_" + shared_pref.preference_file)
        app_facts_dict['send_shared_prefs'] = send_shared_prefs_facts

        # Receivers
        logging.info("Looking for dynamic receivers")
        recv_intents_facts = set()
        for receiver in get_dynamic_receivers(a, d, dx):
            recv_intents_facts.add("i_" + receiver.get_action())
        for receiver in get_static_receivers(a):
            recv_intents_facts.add("i_" + receiver.get_action())
        app_facts_dict['recv_intents'] = recv_intents_facts

        # Shared Prefs Recv
        logging.info("Looking for shared preferences receives")
        recv_shared_prefs_facts = set()
        for shared_pref in get_shared_preferences_reads(a, d, dx):
            recv_shared_prefs_facts.add("sp_" + shared_pref.package + "_" + shared_pref.preference_file)
        app_facts_dict['recv_shared_prefs'] = recv_shared_prefs_facts

        return app_facts_dict
    except Exception as err:
        logging.critical(err)
        logging.critical("Error during analysis of " + apk_filename + ". Skpping")
        return None


def write_facts_to_files(app_facts_dict, app_output_dir):
    logging.info("Writing facts to " + app_output_dir)

    escaped_package_name = escape_quotes(app_facts_dict['package_name'])

    # write packages
    with open(os.path.join(app_output_dir, "packages.pl.partial"), 'w') as f:
        f.write("package('%s','%s').\n" % (escaped_package_name, escape_quotes(app_facts_dict['app_base_file_name'])))

    # write permissions
    with open(os.path.join(app_output_dir, "uses.pl.partial"), 'w') as f:
        for permission in app_facts_dict['permissions']:
            f.write("uses('%s','%s').\n" % (escaped_package_name, escape_quotes(permission)))

    # write sends
    with open(os.path.join(app_output_dir, "sends.pl.partial"), 'w') as f:
        for intent in app_facts_dict['send_intents']:
            f.write("trans('%s','%s').\n" % (escaped_package_name, escape_quotes(intent)))
        for shared_pref in app_facts_dict['send_shared_prefs']:
            f.write("trans('%s','%s').\n" % (escaped_package_name, escape_quotes(shared_pref)))

    # write receivers
    with open(os.path.join(app_output_dir, "receives.pl.partial"), 'w') as f:
        for intent in app_facts_dict['recv_intents']:
            f.write("recv('%s','%s').\n" % (escaped_package_name, escape_quotes(intent)))
        for shared_pref in app_facts_dict['recv_shared_prefs']:
            f.write("recv('%s','%s').\n" % (escaped_package_name, escape_quotes(shared_pref)))


def generate_facts(apk_file_list, output_dir, output_dir_prefix):
    if not os.path.isdir(output_dir):
        logging.info("Output directory " + output_dir + " does not exist. Creating it")
        os.mkdir(output_dir)

    for apk_filename in apk_file_list:
        app_output_dir = os.path.join(output_dir, output_dir_prefix + ntpath.basename(apk_filename))

        if os.path.exists(app_output_dir):
            logging.warning("Output directory " + app_output_dir + " already exists. Skipping analysis of " + file)
            continue

        app_facts_dict = analyse_apk_file(apk_filename)

        if app_facts_dict is None:
            continue

        os.mkdir(app_output_dir)

        write_facts_to_files(app_facts_dict, app_output_dir)


def main():
    parser = argparse.ArgumentParser(description="Collusion facts generator, version %s. Produce the collusion facts for the given android apks. For each specidied android apk file, a directory will be created which stores the extracted collusion facts." % VERSION_NUMBER)
    parser.add_argument("-v", "--verbose",
                        action="store_true", dest="verbose", default=False,
                        help="increase output verbosity")
    parser.add_argument("-o", "--output_dir",
                        action="store", dest="output_dir", default=".",
                        help="set the output directory in which the collusion facts directories will be created.  Directory will be created if it does not exist. Default is '.'")
    parser.add_argument("-p", "--prefix",
                        action="store", dest="output_dir_prefix", default="collusion_facts_",
                        help="set output directory prefix used in the naming of the collusion facts directories. Default is 'collusion_facts_'. Note, this can be set to the empty string ''")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-d', '--directory', dest="apk_dir", metavar='DIR', help = 'a directory containing apks which are to be processed (this recursivly looks in this directory for apk files). All files that are not apk files will be ignored')
    group.add_argument('-a', '--apks', dest="apk_files", metavar='APK', nargs='+', help='apk file(s) to be processing')

    args = parser.parse_args()

    logging_level = logging.WARNING
    if args.verbose:
        logging_level = logging.INFO

    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging_level)

    # Calculate the apk files
    apk_file_list = []
    if (args.apk_files != None):
        apk_file_list = args.apk_files
    elif (args.apk_dir != None):
        apk_file_list = get_all_files_in_dir(args.apk_dir, ".apk")

    logging.info("Version " + VERSION_NUMBER)
    logging.info("Apk files to process: \n\t%s" % str.join("\n\t", apk_file_list))

    if len(apk_file_list) <= 0:
        logging.warning("No apk files specified")
        exit(-1);

    generate_facts(apk_file_list, args.output_dir, args.output_dir_prefix)


if __name__ == "__main__":
    main()