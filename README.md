# f5-security-tester
F5 tool that validate the WAF provide basic security level

# Overview

F5 research team has created a tool that provide easy and fast way to integrate their security testing into their SDLC,
That will ensure their applications are protected and safe with F5 WAF to the basic security level, before releasing to production.

# How it Works

The tool test the protection level by sending various attacks samples, that validate the application is not vulnerable to generic attack types (system independent, general database and javascript), and provide easy and fast feedback loop about the testing results with possible reasons of the failed attacks .

On top of the generic attack types, the tool support testing specific server technologies based on the application components:

- Node.js
- PHP
- MongoDb
- Micorsoft
- Unix/Linux

# Installation

## Prerequisites

Python 2.7+
Python package control (pip):  
Ubuntu/Kali, ```sudo apt-get install -y python-pip```  
Fedora, ```sudo dnf install -y python-pip```  
Install the tool. ```pip install awaf-policy-validator```  

# How to Use

You have to create configuration file at the first time that contain initial information about the testing environment which should include information the application systems :  ```awaf-policy-validator --init```  

The testing results can be found on the same path under "report.json" file.  

The configuration and testing files can be edited based on the testing results to describe exactly the application environments.  

More help information can be found by using the command:  ```awaf-policy-validator --help```  

usage: awaf-policy-validator [-h] [-v] [-i] [-c CONFIG] [-t TESTS] [-r REPORT]  

optional arguments:  
  -h, --help            show this help message and exit  
  -v, --version         show program's version number and exit  
  -i, --init            Initialize Configuration. (default: False)  
  -c CONFIG, --config CONFIG  
                        Configuration File Path. (default: /usr/local/lib/python2.7/dist-packages/awaf_policy_validator/config/config.json)  
  -t TESTS, --tests TESTS   
                        Tests File Path. (default: /usr/local/lib/python2.7/dist-packages/awaf_policy_validator/config/tests.json)  
  -r REPORT, --report REPORT  
                        Report File Save Path. (default: report.json)  
