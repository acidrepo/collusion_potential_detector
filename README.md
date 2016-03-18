# ACID Android App Collusion Potential Detector

This tool is a first approximation to detecting app collusion potential. The tool uses androguard to extract facts about
app communication and used permissions. Extracted facts and a set of prolog rules can be used later to detect the collusion
potential between the apps in the analysed set. The tool is split in two components: the fact generator and the prolog program
Both components can be run consecutively or separately.

## Requirements

Requires Python 2.7. This project relies on Androguard to execute most of the analysis tasks. Specifically, we use Androguard 2.0. That version has a minor bug in 
function call inside the `dvm.py`. This project links directly to a version with that bug so you don't need to change anything
Additionally, the tool uses the comman line SWI-Prolog implementation. In a mac, it can be installed using brew: 
```
brew install swipl
```
## Usage

### Fact Extraction
To extract the facts from a set of Android apps that are stored in a folder:

```
python facts.py [-v] [-r rule_file] [-s]  app_folder result_prefix
```

Where:
- `-v`: Makes the tool give information about the fact extraction process
- `-r rule_file`: append the `rule_file` to the list of generated facts for its usage in swi-prolog. In our case, collusion rules are defined in `collusion_rules.pl`
- `-s`: Add rules to account external storage as a possible communication channel.  
- `app_folder`: Specifies the folder where the apps to be analysed are stored
- `result_prefix`: Is the prefix that will be added to all output files

This tool generates three output files:
- `result_prefix_uses.txt`: Prolog facts about permissions used by the apps
- `result_prefix_trans.txt`: Prolog facts about the communication channels used by the apps to send information to other apps
- `result_prefix_recv.txt`: Prolog facts about the communication channels used by the apps to receive information from other apps
- `result_prefix_intent_send_stats`: Stats about the actions detected by intents used to send information to other apps/components
- `result_prefix_intent_recv_stats`: Stats about the actions detected by intent filters used to receive information from other apps/components
- `rule_file_program.pl`: A Prolog program that includes the facts generated after app analysis and the collusion rules specificed by `rule_file.pl`


### Prolog Execution
The Prolog program can be executed using the following command
```
python prolog.py [-v] [-f intent_folder] prolog_file collusion kind
```

Where:
- `-v`: Puts the program in verbose mode to provide additional output
- `-f intent_folder`: Removes all facts related to the intents actions included in the `intent_folder`. Intent actions should can be organized inside different files inside the folder (one intent action per line).
- `prolog_file`: A file including app facts and the collusion rule set. It should be the output prolog file of the `facts.py` execution
- `collusion_kind`: The kind of collusion that we are looking for. The following values are possible: colluding_info, colluding_money1, colluding_money2, colluding_service

This tool outputs a list of all collusion app sets found in the `prolog_file`. It includes the apps in the set, and the channels used to communicate
 
### Executing both tools 

To execute the fact extraction process and the prolog rules with one command you can:
```
python collusion_finder.py [-v] [-s] [-f intent_folder]  app_folder rule_file
```

Where:
- `-v`: Puts the program in verbose mode to provide additional output
- `-s`: Add rules to account external storage as a possible communication channel.
- `-f intent_folder`: Removes all facts related to the intents actions included in the `intent_folder`. Intent actions should can be organized inside different files inside the folder (one intent action per line).
- `app_folder`: Specifies the folder where the apps to be analysed are stored
- `rule_file`: The file with the collusion rules. In our case, collusion rules are defined in `collusion_rules.pl`


This tool outputs the found colluding app sents, including the communication channels used. All the auxiliary files required during execution, except the prolog program, are deleted after execution


## Testing

To test the fact extraction process you can use py.test
```
pip install py.test
```

We have developed a set of colluding applications for Android to test this approach. The developed test can be found in an encrypted file inside the tests/apk folder. To request access to the file key to decrypt the TrueCrypt volume, you can write and email to
Jorge dot Blasco dot 1 at city dot ac dot uk.

## Limitations

- At the moment, the following communication channels are detected: External Storage, Implicit Intents and SharedPreferences
- Variable tracking cannot go beyond the method scope. This means that some String values will not be gathered
- The aim of this tool is to perform a quick filter over an app set so more sophisticated analysis can be executed. Therefore, We do not try to track if a sensitive resource has been shared or not through the communication channel


## TODOs
- Increase the tests to cover all the apps in the apk test set
- Add more communication channels
- Improve the string and variable tracking for obtaining intent actions and other required variables
- Properly comment python code
