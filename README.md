# f5-tester
Advanced Web Application Firewall Policy Validation Tool

# Overview

F5 research team has created a tool that provide easy and fast way to integrate their security testing into their SDLC,
That will ensure their applications are protected and safe with F5 WAF to the basic security level, before releasing to production.

# How it Works

The tool test the protection level by sending various attacks samples that validate the application is not vulnerable to generic system independent, general database and javascript attack types, along with specific application server technologies that web application contain, and provide easy and fast feedback loop about the testing results with possible reasons of the failed attacks .

The tool support testing attack types samples to ensure the of following attack types:

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

Python 2.7+
Python package control (pip):
Ubuntu/Kali, ```sudo apt-get install -y python-pip```.
Fedora, ```sudo dnf install -y python-pip```.
Install the tool. ```pip install awaf-policy-validator```.

# How to Use
