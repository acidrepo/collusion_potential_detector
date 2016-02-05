from logging import Logger, DEBUG
import logging
import sys
sys.path.append("../")
from acid_detectors.implicit_intents import get_implicit_intents, get_dynamic_receivers, get_static_receivers

sys.path.append("../androguard-acid/")
from androguard.core.analysis.analysis import VMAnalysis
from androguard.core.analysis.ganalysis import GVMAnalysis
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.misc import AnalyzeAPK

__author__ = 'jorgeblasco'



sender_file="apks/Send_WeatherApp_StaticIntent.apk"
logging.basicConfig(level=logging.INFO)


def test_intent_writes():
    a,d, dx = AnalyzeAPK("../tests/apks/Send_WeatherApp_StaticIntent.apk")
    x = get_implicit_intents(apk=a,d=d,dx=dx)
    actions = ["readcontacts","stop","gettasks","sms","start"]
    for i in actions:
        assert i in [bi.action for bi in x]
    assert len(x) == len(actions)

def test_intent_writes_init():
    a,d, dx = AnalyzeAPK("../tests/apks/DocViewer_Benign.apk")
    x = get_implicit_intents(apk=a,d=d,dx=dx)
    actions = ["android.intent.action.SEND"]
    for i in actions:
        assert i in [bi.action for bi in x]
    assert len(x) == len(actions)

def test_static_intent_receives():
    a,d, dx = AnalyzeAPK("../tests/apks/Rec_TaskManager_StaticIntent.apk")
    x = get_static_receivers(apk=a)
    actions = ["stop","gettasks","start","android.intent.action.MAIN"]
    for i in actions:
        assert i in [bi.get_action() for bi in x]
    for i in x:
        print i.get_action()
    assert len(x) == len(actions)


def test_weatherapp_intent_receives():
    a,d, dx = AnalyzeAPK("../tests/apks/Send_WeatherApp_StaticIntent.apk")
    x = get_static_receivers(apk=a)
    x.extend(get_dynamic_receivers(a,d,dx))
    actions = ['android.intent.action.MAIN',"gettasks_response","readcontacts_response"]
    for i in actions:
        assert i in [bi.get_action() for bi in x]
    for i in x:
        print i.get_action()
    assert len(x) == len(actions)

def test_fwd_intent_receives():
    a,d, dx = AnalyzeAPK("../tests/apks/FWD_Gaming_Intent.apk")
    x = get_static_receivers(apk=a)
    x.extend(get_dynamic_receivers(a,d,dx))
    actions = ['android.intent.action.MAIN',"action.SEND.WHATEVER"]
    for i in actions:
        assert i in [bi.get_action() for bi in x]
    for i in x:
        print i.get_action()
    assert len(x) == len(actions)

