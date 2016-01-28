from logging import Logger, DEBUG
import logging
import sys
sys.path.append("../")
from acid_detectors.shared_preferences import get_shared_preferences_reads, get_shared_preferences_writes

sys.path.append("../androguard/")
from androguard.core.analysis.analysis import VMAnalysis
from androguard.core.analysis.ganalysis import GVMAnalysis
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.misc import AnalyzeAPK

__author__ = 'jorgeblasco'



sender_file="apks/Rec_RSS_Reader_SharedPreferences.apk"
logging.basicConfig(level=logging.INFO)


def test_tainted_shared_preferences_reads():
    a,d, dx = AnalyzeAPK("../tests/apks/Rec_RSS_Reader_SharedPreferences.apk")
    x = get_shared_preferences_reads(apk=a,d=d,dx=dx)
    assert len(x) == 1
    assert x[0].package == 'com.acid.colluding.filemanager'
    assert x[0].preference_file == 'PrefsFile'
    assert x[0].operation == 'read'

def test_tainted_shared_preferences_writes():
    a,d, dx = AnalyzeAPK("../tests/apks/Send_FileManager_SharedPreferences.apk")
    x = get_shared_preferences_writes(apk=a,d=d,dx=dx)
    for i in x:
        print i.package
        print i.preference_file
        print i.operation
    assert len(x) == 1
    assert x[0].package == 'com.acid.colluding.filemanager'
    assert x[0].preference_file == 'PrefsFile'
    assert x[0].operation == 'write'