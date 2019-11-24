# f5-waf-tester
F5 testing tool that ensure basic security level.

# Overview

F5 research team has created a tool that provide easy and fast way to integrate their security testing into their SDLC,\
That will ensure their applications are protected and safe with F5 WAF to the basic security level, before releasing to production.\

# How it Works

The tool will test the protection level by sending various attacks samples, that validate the application is not vulnerable to generic attack types (system independent, general database and javascript), and provide easy and fast feedback loop about the testing results with possible reasons of the failed attacks that related to F5 WAF.

On top of the generic attack types tests, the tool support testing specific server technologies based on the application components:

- Node.js
- PHP
- MongoDb
- Micorsoft
- Unix/Linux
- XML
- Java Servlets/JSP
- ASP.NET
- Python

# Installation

## Prerequisites

Python 2.7+\
Python package control (pip):\
Ubuntu/Kali, ```sudo apt-get install -y python-pip```  
Fedora, ```sudo dnf install -y python-pip``` 

Install the tool. ```pip install git+https://github.com/f5devcentral/f5-waf-tester.git```  

# How to Use

1. First you have to create configuration file at the first time that contain initial information about the testing environment which should \ include information the application server technologies :  ```f5-waf-tester --init``` 

2. After the first init, config file is created and can be maintanted based on the test results.

usage: f5-waf-tester [-h] [-v] [-i] [-c CONFIG] [-t TESTS] [-r REPORT]\

optional arguments:\
  -h, --help            show this help message and exit\
  -v, --version         show program's version number and exit\
  -i, --init            Initialize Configuration. (default: False)\
  -c CONFIG, --config CONFIG\
                        Configuration File Path. (default: config.json)
  -t TESTS, --tests TESTS\
                        Tests File Path. (default: tests.json)\
  -r REPORT, --report REPORT\
                        Report File Save Path. (default: report.json)
                        

More help information can be found by using the command:  ```f5-waf-tester --help``` 

3. The testing results can be found on the same path under "report.json" file.\

The testing results can be found on the same path under "report.json" file.\
The configuration and testing files can be edited based on the testing results to describe exactly the application environments.\

The configuration and testing files can be edited based on the testing results to describe exactly the application environments.\

e/g Edit the config file ("config.json") to exclude or include tests based on the tests results:
Adding server technologies based on the application enviorment:

```}
      "include": {
      "attack_type": [
      ], 
      "id": [
      ], 
      "system": [
        "Unix/Linux", 
        "Node.js", 
        "MongoDb"
      ]
}
```


 

