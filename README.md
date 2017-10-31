# ACID Android App Collusion Potential Detector

This tool is a first approximation to detecting app collusion potential. The tool uses androguard to extract facts about
app communication and used permissions. Extracted facts and a set of Prolog rules can be used later to detect the collusion
potential between the apps in the analysed set. The tool is split in three components: the fact generator, the Prolog generator and the detection tool (that executed the Prolog program). These programs should be run in sequence.

## Requirements

Requires Python 2.7. This project relies on Androguard to execute most of the analysis tasks. Specifically, we use Androguard 2.0. That version has a minor bug in 
function call inside the `dvm.py`. This project links directly (using git submodules) to a version with that bug fixed so you don't need to change anything
Additionally, the tool uses the command line SWI-Prolog implementation.

## Installation

We provide instructions for installation for Ubuntu 16.04 (LTS). Even though these instructions have only been tested for Ubuntu 16.04, they should work on newer versions of Ubuntu too. We assume a fresh install of Ubuntu. If you are using an existing deployment of Ubuntu then you may already have some of the required packages installed.

### Install packages

```
sudo apt install git python-setuptools swi-prolog
```

### Clone git repository

We clone the git repository with the `--recursive` option to clone the main repository along with submodules.

```
git clone --recursive https://github.com/acidrepo/collusion_potential_detector.git ~/Desktop/collusion_potential_detector
```

If you don't use `--recursive`, then you can clone the androguard sub-module manually:

```
cd ~/Desktop/collusion_potential_detector/androguard-acid

git submodule init

git submodule update
```

### Install patched version of Androguard

```
cd ~/Desktop/collusion_potential_detector/androguard-acid

sudo python setup.py install
```

### Install to system directory

```
sudo mv ~/Desktop/collusion_potential_detector /usr/local/

sudo chown -R root:root /usr/local/collusion_potential_detector

sudo ln -s /usr/local/collusion_potential_detector/generate_facts.py /usr/local/bin/generate_facts

sudo ln -s /usr/local/collusion_potential_detector/generate_prolog.py /usr/local/bin/generate_prolog

sudo ln -s /usr/local/collusion_potential_detector/detect_collusion.py /usr/local/bin/detect_collusion
```

## Running the tools

### Step 1: Generation of collusion facts
The first step is to generate the collusion facts for a set of apps. The tool will extract the facts and write them to a directory per analysed app.

For exact usage of the tool run:

```
generate_facts --help
```

This tool generates various output files per analysed apk file:
- `packages.pl.partial`: Prolog facts about the apk package name.
- `uses.pl.partial`: Prolog facts about permissions used by the apps.
- `trans.pl.partial`: Prolog facts about the communication channels used by the apps to send information to other apps.
- `recv.pl.partial`: Prolog facts about the communication channels used by the apps to receive information from other apps.


### Step 2: Generation of Prolog program
The Prolog progam is generated after the collusion fact directories have been created in Step 1.

For exact usage of the tool run:

```
generate_prolog --help
```

### Step 3: Detection of collusion 
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
- The aim of this tool is to perform a quick filter over an app set so more sophisticated analysis can be executed. Therefore, we do not try to track if a sensitive resource has been shared or not through the communication channel


## TODOs
- Increase the tests to cover all the apps in the apk test set
- Add more communication channels
- Improve the string and variable tracking for obtaining intent actions and other required variables
- Properly comment python code
