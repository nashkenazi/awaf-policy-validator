# f5-tester
Advanced Web Application Firewall Policy Validation Tool

# Overview

F5 research team has created a tool to provide customers an easy way to integrate security testing into their SDLC,
That ensuring their applications are protected with the basic security level before releasing to production.
The tool provide testing suite that cover basic attack types along with application server technologies that web applications must have,  and provide easy feedback loop about the possible reasons if the policy is not blocked the attack.

The tool support testing samples of following attack types:

- SQL-Injection
- NoSQL Injection
- Cross Site Scripting (XSS)
- Command Execution (Unix/Windows)
- Path Traversal
- Predictable Resource Location
- Detection Evasion (Null in The Request/Alternative Data stream Access)
- Insecure De-serialization



On top of the generic attack types, the tool support that following specific testing the following server technologies:

- Node.js
- PHP
- MongoDb
- Micorsoft
- Unix/Linux

# Installation

## Prerequisites

Python 2.7+.
A C compiler, Python headers, etc. (are needed to compile several dependencies):
On Ubuntu / Kali, ```sudo apt-get install -y python-pip```
On Fedora, ```sudo dnf install -y python-pip```
Install the tool. ```pip install awaf-policy-validator```
