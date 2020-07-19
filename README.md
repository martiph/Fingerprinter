# Fingerprinter
````
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@################################@
@########                ########@
@########                ########@
@########        ################@
@########        ################@
@########        ################@
@########              ##########@
@########              ##########@
@########        ################@
@########        ################@
@########        ##Fingerprinter#@
@########        #######by#######@
@########        #####Philip#####@
@########        #####Marti######@
@################################@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
````
Welcome to the *Fingerprinter* project. The main purpose of this project is to provide a proof-of-concept implementation of a remote operating system fingerprinting method based on protocol header analysis. In addition there is also a function for a cloud provider detection mechanism based on TCP/IP networking. This repository is part of my thesis to receive my bachelor's degree in computer sciences with specialization in information security from `Fernfachhochschule Schweiz (FFHS)`. Anyone interested in the thesis can contact me (only available in german).

## Installation

First, make sure you have `python-3.8` (including `pip`) locally installed and added to your PATH. Then clone this repository (`git clone https://github.com/martiph/Fingerprinter.git`) onto your local machine and create a python virtual environment (virtualenv). To install all necessary packages, activate the virtualenv and run `pip install -r /path/to/requirements.txt`. Probably you will need to alter the command slightly. For example if you work on a linux-system, you probably need to use `pip3` instead of `pip`.
An example on how to create and activate a virtual environment is listed below.
````bash
pip install virtualenv
virtualenv FingerprinterEnv
./FingerprinterEnv/Scripts/Activate.ps1 # on Windows (PowerShell)
source ./FingerprinterEnv/bin/activate # on Linux (Bash)
pip install -r /path/to/requirements.txt
````
`requirements.txt` was generated after development using `pip freeze > requirements.txt`.

## Usage

If you want to use the os-fingerprinting function, you need to run the program as root/administrator. Independent on which function you want to use, you need to activate the virtual environment first (like described above).
To run the application from the root of the git repository, use the following command:
````bash
python ./fingerprinter/fingerprinterapp.py
````
The following commands are valid in `fingerprinter`:  
os-fingerprinting  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- this command is used to fingerprint a windows or ubuntu system  
cloudprovider-detection  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- this command is used to detect if AWS or Azure is used to host the system    
exit  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- exits this application

## Contribution

You are welcome to open an issue or create a pull request.

Version numbers follow the semantic versioning (https://semver.org/) principle.
