# ACID Android App Collusion Potential Detector

This tool is a first approximation to detecting app collusion potential. The tool uses androguard to extract facts about
app communication and used permissions. Extracted facts and a set of prolog rules can be used later to detect the collusion
potential between the apps in the analysed set. The tool is split in three components: the fact generator, the prolog generator and the detection tool (that executed the prolog program). These programs should be run in sequence.

## Requirements

Requires Python 2.7. This project relies on Androguard to execute most of the analysis tasks. Specifically, we use Androguard 2.0. That version has a minor bug in 
function call inside the `dvm.py`. This project links directly to a version with that bug fixed so you don't need to change anything
Additionally, the tool uses the comman line SWI-Prolog implementation.

## Running the Tools

### Step 1: Generation of Collusion Facts.
The first step is to generate the collusion facts for a set of apps. The tool will extract the facts and write them to a directory per analysed app.

For exact usage of the tool run:

```
generate_facts --help
```

This tool generates various output files per analysed apk file:
- `packages.pl.partial: Prolog facts about the apk package name.
- `uses.pl.partial`: Prolog facts about permissions used by the apps.
- `trans.pl.partial`: Prolog facts about the communication channels used by the apps to send information to other apps.
- `recv.pl.partial`: Prolog facts about the communication channels used by the apps to receive information from other apps.


### Step 2: Generation of Prolog Program
The Prolog progam is generated after the collusion fact directories have been created in Step 1.

For exact usage of the tool run:

```
generate_prolog --help
```

### Step 3: Detection of Collusion 
The final step is to execute the Prolog program generated in Step 2. A python program controls the execution of the Prolog progam and acts as a wrapper.

For exact usage of the tool run:

```
detect_collusion --help
```

This tool outputs a list of all collusion app sets found in the `prolog_file`. It includes the apps in the set, and the channels used to communicate.
 
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
