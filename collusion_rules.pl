/*
* There are certain permissions that provide an app with the capability of gathering
* sensitive information from the device. If any of those permissions is present in
* an app it means that it will have the capability to read sensitive information.
* This is represented by the predicate information_gathering(App_a) :- uses(p_info,App_a)
* where p_info are all permissions that allow inforamation gathering. See document XX
* This predicate means that if an app uses the read_contacts permission, it is capable
* of gathering information.
*
* List of permissions, and corresponding constants, that generate information loss
* -- LOW --
* ACCESS_COARSE_LOCATION - p_ac
* ACCESS_NETWORK_STATE -p_ans
* ACCESS_WIFI_STATE - p_aws
* GET_PACKAGE_SIZE - p_gps
* GET_TASKS - p_gt
* READ_HISTORY_BOOKMARKS - p_rhb
* READ_SYNC_SETTINGS - p_rss
* READ_SYNC_STATS - p_rsst
*/
information_gathering(A):- uses(A,'android.permission.ACCESS_COARSE_LOCATION').
information_gathering(A):- uses(A,'android.permission.ACCESS_NETWORK_STATE').
information_gathering(A):- uses(A,'android.permission.ACCESS_WIFI_STATE').
information_gathering(A):- uses(A,'android.permission.GET_PACKAGE_SIZE').
information_gathering(A):- uses(A,'android.permission.READ_HISTORY_BOOKMARKS').
information_gathering(A):- uses(A,'android.permission.READ_SYNC_SETTINGS').
information_gathering(A):- uses(A,'android.permission.GET_TASKS').
information_gathering(A):- uses(A,'android.permission.READ_SYNC_STATS').
/*
* -- MEDIUM --
* READ_CONTACTS - p_rc
* READ_CALL_LOG - p_rcl
*/
information_gathering(A):- uses(A,'android.permission.READ_CONTACTS').
information_gathering(A):- uses(A,'android.permission.READ_CALL_LOG').
/*
* -- HIGH --
* GET_ACCOUNTS - p_ga
* ACCESS_FINE_LOCATION - p_afl
* BIND_APPWIDGET - p_aa
* AUTHENTICATE_ACCOUNTS - p_ba
* BIND_INPUT_METHOD - p_bim
* BIND_TEXT_SERVICE - p_bts
* BIND_VPN_SERVICE - p_bvs
* BODY_SENSORS - p_bs
* CAMERA - p_c
* PROCESS_OUTGOING_CALLS - p_poc
* MANAGE_ACCOUNTS - p_ma
* READ_EXTERNAL_STORAGE - p_res
* GET_ACCOUNTS - p_ga
* READ_CALENDAR - p_rc
* READ_PHONE_STATE - p_rps
* READ_SOCIAL_STREAM - p_rss
* READ_PROFILE - p_rp
* READ_USER_DICTIONARY - p_rud
* RECEIVE_MMS - p_rmms
* SUBSCRIBED_FEEDS_READ - p_sfr
* RECEIVE_SMS - p_rsms
* RECORD_AUDIO - p_ra
* USE_CREDENTIALS - p_uc
* READ_LOGS - p_rl
* BIND_NOTIFICATION_LISTENER_SERVICE - p_bnls
*/
information_gathering(A):- uses(A,'android.permission.GET_ACCOUNTS').
information_gathering(A):- uses(A,'android.permission.ACCESS_FINE_LOCATION').
information_gathering(A):- uses(A,'android.permission.BIND_APPWIDGET').
information_gathering(A):- uses(A,'android.permission.AUTHENTICATE_ACCOUNTS').
information_gathering(A):- uses(A,'android.permission.BIND_INPUT_METHOD').
information_gathering(A):- uses(A,'android.permission.BIND_TEXT_SERVICE').
information_gathering(A):- uses(A,'android.permission.BIND_VPN_SERVICE').
information_gathering(A):- uses(A,'android.permission.BODY_SENSORS').
information_gathering(A):- uses(A,'android.permission.CAMERA').
information_gathering(A):- uses(A,'android.permission.PROCESS_OUTGOING_CALLS').
information_gathering(A):- uses(A,'android.permission.MANAGE_ACCOUNTS').
information_gathering(A):- uses(A,'android.permission.READ_EXTERNAL_STORAGE').
information_gathering(A):- uses(A,'android.permission.GET_ACCOUNTS').
information_gathering(A):- uses(A,'android.permission.READ_CALENDAR').
information_gathering(A):- uses(A,'android.permission.READ_PHONE_STATE').
information_gathering(A):- uses(A,'android.permission.READ_SOCIAL_STREAM').
information_gathering(A):- uses(A,'android.permission.READ_PROFILE').
information_gathering(A):- uses(A,'android.permission.READ_USER_DICTIONARY').
information_gathering(A):- uses(A,'android.permission.RECEIVE_MMS').
information_gathering(A):- uses(A,'android.permission.SUBSCRIBED_FEEDS_READ').
information_gathering(A):- uses(A,'android.permission.RECEIVE_SMS').
information_gathering(A):- uses(A,'android.permission.RECORD_AUDIO').
information_gathering(A):- uses(A,'android.permission.USE_CREDENTIALS').
information_gathering(A):- uses(A,'android.permission.READ_LOGS').
information_gathering(A):- uses(A,'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE').
/*
* There are certain permissions that provide an app with the capability of establishing
* communication channels to communicate outside the devie. If any of those permissions
* is present in an app it means that it will have the capability extract information.
* This is represented by the predicate outside_communication(App_a) :- uses(p_internet,
* App_a). There should be one predicat for each permissions that allows external
* communication.
* List of permissions, and corresponding constants, that enable outside communication
* -- OVERT --
* BIND_NFC_SERVICE - p_bns
* BIND_PRINT_SERVICE - p_bp
* BIND_VPN_SERVICE - p_bvs
* BLUETOOTH - p_b
* BLUETOOTH_ADMIN p_ba
* CHANGE_WIFI_MULTICAST_STATE p_cwms
* NFC - p_nfc
* CHANGE_WIFI_STATE - p_cws
* INTERNET - p_i
* CHANGE_NETWORK_STATE - p_cns
* SEND_SMS - p_ssms
* TRANSMIT_IR - p_ti
*/
outside_communication(A):- uses(A,'android.permission.BIND_NFC_SERVICE').
outside_communication(A):- uses(A,'android.permission.BIND_PRINT_SERVICE').
outside_communication(A):- uses(A,'android.permission.BIND_VPN_SERVICE').
outside_communication(A):- uses(A,'android.permission.BLUETOOTH').
outside_communication(A):- uses(A,'android.permission.BLUETOOTH_ADMIN').
outside_communication(A):- uses(A,'android.permission.CHANGE_WIFI_MULTICAST_STATE').
outside_communication(A):- uses(A,'android.permission.NFC').
outside_communication(A):- uses(A,'android.permission.CHANGE_WIFI_STATE').
outside_communication(A):- uses(A,'android.permission.INTERNET').
outside_communication(A):- uses(A,'android.permission.CHANGE_NETWORK_STATE').
outside_communication(A):- uses(A,'android.permission.SEND_SMS').
outside_communication(A):- uses(A,'android.permission.TRANSMIT_IR').
/*
* -- COVERT --
* MANAGE_ACCOUNTS - p_ma
* USE_SIP - p_us
* WRITE_CALENDAR - p_wc
* WRITE_HISTORY_BOOKMARKS - p_whb
* WRITE_PROFILE - p_wp
* WRITE_SOCIAL_STREAM - p_wss
*
* outside_communication(A):- uses(p_ma,A).
* outside_communication(A):- uses(p_us,A).
* outside_communication(A):- uses(p_wc,A).
* outside_communication(A):- uses(p_whb,A).
* outside_communication(A):- uses(p_wp,A).
* outside_communication(A):- uses(p_wss,A).
*/

/*
* There are certain permissions that provide an app with the ability to perform actions
* that can result in a monetary charge for the user. These permissions are represented
* by the predicate money(App_a) ;- uses(p_call,App_a). This means that if App_a uses
* permission p_call it is capable of charging the user.
*
* List of permissions, and corresponding constants, that generate money theft
* BIND_NFC_SERVICE - p_bns
* CALL_PHONE - p_cp
* SEND_SMS - p_ssms
*/
money(A) :- uses(A,'android.permission.BIND_NFC_SERVICE').
money(A) :- uses(A,'android.permission.CALL_PHONE').
money(A) :- uses(A,'android.permission.SEND_SMS').
/*
* There are certain permissions that provide an app with the ability to control
* the device resources (camera, data, internet, etc.). These permissions are represented
* by the predicate control_service(App_a) ;- uses(p_killprocess,App_a). This means that if
* App_a uses permission p_call it is capable of charging the user. This kind of
* permission can be used to sabotage the device (denial of service) or to perform service
* misuse (SPAM). There should be one predicat for each permissions that allows to control
* a service.
*
* List of permissions, and corresponding constants, that allow service control
* --LOW--
* SET_TIME_ZONE - p_stz
* SET_WALLPAPER - p_sw
* SET_WALLPAPER_HINTS - p_swh
*/
control_service(A) :- uses(A,'android.permission.SET_TIME_ZONE').
control_service(A) :- uses(A,'android.permission.SET_WALLPAPER').
control_service(A) :- uses(A,'android.permission.SET_WALLPAPER_HINTS').
/*
* --MEDIUM--
* CLEAR_APP_CACHE - p_cac
* FLASHLIGHT - p_f
* CHANGE_WIFI_MULTICAST_STATE - p_cwms
* MODIFY_AUDIO_SETTINGS - p_mas
* SET_ALARM - p_sa
* VIBRATE - p_v
*/
control_service(A) :- uses(A,'android.permission.CLEAR_APP_CACHE').
control_service(A) :- uses(A,'android.permission.FLASHLIGHT').
control_service(A) :- uses(A,'android.permission.CHANGE_WIFI_MULTICAST_STATE').
control_service(A) :- uses(A,'android.permission.MODIFY_AUDIO_SETTINGS').
control_service(A) :- uses(A,'android.permission.SET_ALARM').
control_service(A) :- uses(A,'android.permission.VIBRATE').


/*
* --HIGH--
* BIND_DEVICE_ADMIN - p_bda
* CALL_PHONE - p_cp
* CHANGE_CONFIGURATION - p_cc
* CHANGE_WIFI_STATE - p_cws
* CHANGE_NETWORK_STATE - p_cns
* DISABLE_KEYGUARD - p_dk
* GET_ACCOUNTS - p_ga
* INSTALL_SHORTCUT - p_is
* KILL_BACKGROUND_PROCESSES - p_kbp
* MANAGE_ACCOUNTS - p_ma
* MANAGE_DOCUMENTS - p_md
* PERSISTENT_ACTIVITY - p_pa
* PROCESS_OUTGOING_CALLS - p_poc
* REORDER_TASKS - p_rt
* WRITE_EXTERNAL_STORAGE - p_wes
* SEND_SMS - p_ssms
* SET_PREFERRED_APPLICATIONS - p_spa
* SYSTEM_ALERT_WINDOW - p_saw
* SUBSCRIBED_FEEDS_WRITE - p_sfw
* UNINSTALL_SHORTCUT - p_us
* WAKE_LOCK - p_wl
* WRITE_CALL_LOG - p_wcl
* WRITE_CALENDAR - p_wc
* WRITE_HISTORY_BOOKMARKS - p_whb
* WRITE_PROFILE - p_wp
* WRITE_SETTINGS - p_ws
* WRITE_SOCIAL_STREAM - p_wss
* WRITE_SYNC_SETTINGS - p_wsse
* WRITE_USER_DICTIONARY - p_wud
* RESTART_PACKAGES - p_rp
* WRITE_APN_SETTINGS - p_was
*/
control_service(A) :- uses(A,'android.permission.BIND_DEVICE_ADMIN').
control_service(A) :- uses(A,'android.permission.CALL_PHONE').
control_service(A) :- uses(A,'android.permission.CHANGE_CONFIGURATION').
control_service(A) :- uses(A,'android.permission.CHANGE_WIFI_STATE').
control_service(A) :- uses(A,'android.permission.CHANGE_NETWORK_STATE').
control_service(A) :- uses(A,'android.permission.DISABLE_KEYGUARD').
control_service(A) :- uses(A,'android.permission.GET_ACCOUNTS').
control_service(A) :- uses(A,'android.permission.INSTALL_SHORTCUT').
control_service(A) :- uses(A,'android.permission.KILL_BACKGROUND_PROCESSES').
control_service(A) :- uses(A,'android.permission.MANAGE_ACCOUNTS').
control_service(A) :- uses(A,'android.permission.MANAGE_DOCUMENTS').
control_service(A) :- uses(A,'android.permission.PERSISTENT_ACTIVITY').
control_service(A) :- uses(A,'android.permission.PROCESS_OUTGOING_CALLS').
control_service(A) :- uses(A,'android.permission.REORDER_TASKS').
control_service(A) :- uses(A,'android.permission.WRITE_EXTERNAL_STORAGE').
control_service(A) :- uses(A,'android.permission.SEND_SMS').
control_service(A) :- uses(A,'android.permission.SET_PREFERRED_APPLICATIONS').
control_service(A) :- uses(A,'android.permission.SYSTEM_ALERT_WINDOW').
control_service(A) :- uses(A,'android.permission.SUBSCRIBED_FEEDS_WRITE').
control_service(A) :- uses(A,'android.permission.UNINSTALL_SHORTCUT').
control_service(A) :- uses(A,'android.permission.WAKE_LOCK').
control_service(A) :- uses(A,'android.permission.WRITE_CALL_LOG').
control_service(A) :- uses(A,'android.permission.WRITE_CALENDAR').
control_service(A) :- uses(A,'android.permission.WRITE_HISTORY_BOOKMARKS').
control_service(A) :- uses(A,'android.permission.WRITE_PROFILE').
control_service(A) :- uses(A,'android.permission.WRITE_SETTINGS').
control_service(A) :- uses(A,'android.permission.WRITE_SOCIAL_STREAM').
control_service(A) :- uses(A,'android.permission.WRITE_SYNC_SETTINGS').
control_service(A) :- uses(A,'android.permission.WRITE_USER_DICTIONARY').
control_service(A) :- uses(A,'android.permission.RESTART_PACKAGES').
control_service(A) :- uses(A,'android.permission.WRITE_APN_SETTINGS').



/*
* If there are two apps, App_a and App_b such as App_a gathers information, App_b
* extracts information and there is a communication path between the two apps (P)
* Then, the two apps have the ability to collude to extract sensitive information
* from the device. The set of colluding apps that take part in the potential attack
* are returned in P. Apps that encrypt the user information are also included in
* this predicate.
*/
colluding_info(A,B,P):- information_gathering(A),outside_communication(B),comm(A,B,P).

/*
* Apps that charge the user with something and take the information from other apps.
*/
colluding_money1(A,B,P):- money(B),comm(A,B,P).
/*
* Similar, but App_b uses the internet connection to obtain the charging inforamtion.
*/
colluding_money2(A,B,P):- money(B),outside_communication(A),comm(A,B,P).
/*
* An app that acts as a bot and another app that receives the commands from the C&C
* server. This also includes the case of ransom apps.
*/
colluding_service(A,B,P):- control_service(B),outside_communication(A),comm(A,B,P).

colluding(A,B,P):- colluding_info(A,B,P).
colluding(A,B,P):- colluding_money1(A,B,P).
colluding(A,B,P):- colluding_money2(A,B,P).
colluding(A,B,P):- colluding_service(A,B,P).


/* A is an app, B is another app, [] is the communication path (in apps) between A and B including them */

comm(A,B,[A|B]) :- trans(A,C),recv(B,C), A\=B.
comm(A,B,[A|[L|B]]) :- trans(A,C),recv(D,C), A\=D,comm(D,B,[L|B]), A\=B,not_member(A,L).

not_member(_, []) :- !.
not_member(X,B) :- X \= B.
not_member(X, [Head|Tail]) :- X \= Head,not_member(X, Tail).

/* A is an app, B is another app, [C] is the communication path (in communication channels) between A and B including them */

channel([A|B],[C]) :- trans(A,C),recv(B,C), A\=B.
channel([A|[D|B]],[C|K]) :- trans(A,C),recv(D,C), A\=D,channel([D|B],K).





/* 
* Calls to obtain collusion results:
*  findall(P,colluding_info(A,B,P),Ps).
*  findall(P,colluding_money1(A,B,P),Ps).
*  findall(P,colluding_money2(A,B,P),Ps).
*  findall(P,colluding_service(A,B,P),Ps).
*  findall(P,comm(A,B,P),Ps).
*	findnsols(30,P,colluding_info(A,B,P),Ps).
*/