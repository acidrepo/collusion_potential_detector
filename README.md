# ACID Android App Collusion Potential Detector

This tool is a first approximation to detecting app collusion potential. The tool uses androguard to extract facts about
app communication and used permissions. Extracted facts and a set of prolog rules can be used later to detect the collusion
potential between the apps in the analysed set. The tool is split in two components: the fact generator and the prolog program
At the moment, both components must be run separately.

## Requirements

This project relies on Androguard to execute most of the analysis tasks. Specifically, we use Androguard 2.0. That version has a minor bug in 
function call inside the `dvm.py`. This project links directly to a version with that bug so you don't need to change anything


## Usage

You will need the latests version of Androguard to use the fact extractor. Once you have everyting placed in one folder you can
```
python prolog_fact_generator.py [-v] folder result_prefix
```

Where:
- `-v`: Makes the tool give information about the fact extraction process
- `folder`: Specifies the folder where the apps to be analysed are stored
- `result_prefix`: Is the prefix that will be added to all output files

The tool generates three output files:
- `result_prefix_uses.txt`: Prolog facts about permissions used by the apps
- `result_prefix_trans.txt`: Prolog facts about the communication channels used by the apps to send information to other apps
- `result_prefix_recv.txt`: Prolog facts about the communication channels used by the apps to receive information from other apps

Using the generated files along with the `collusion_rules.pl` file, you can obtain a list of apps with collusion potential and the channels they use to communicate

## Testing

To test this program we use py.test
```
pip install py.test
```

We have developed a set of colluding applications for Android to test this approach. However, in this repo you will find the apk folder empty. To request access to the app set, you can write and email to
Jorge dot Blasco dot 1 at city dot ac dot uk.

## Limitations

- At the moment, the following communication channels are detected: External Storage, Implicit Intents and SharedPreferences
- Variable tracking cannot go beyond the method scope. This means that some String values will not be gathered
- The aim of this tool is to perform a quick filter over an app set so more sophisticated analysis can be executed. Therefore, We do not try to track if a sensitive resource has been shared or not through the communication channel


## TODOs
- Create a streamline version of the tool that does all computing automatically. We need to select a Python interface for SWI-Prolog for that
- Add more communication channels
- Improve the string and variable tracking for obtaining intent actions and other required variables
- Add a filtering step that takes out common intent actions to reduce false positives. Look into XX folder to build the filter
- Properly comment python code
