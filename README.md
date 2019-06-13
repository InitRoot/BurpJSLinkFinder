#  BurpJSLinkFinder - Find links within JS files.
Burp Extension for a passive scanning JS files for endpoint links.
Copyright (c) 2019 Frans Hendrik Botes
Credit to https://github.com/GerbenJavado/LinkFinder for the idea and regex

## Setup
For use with the professional version of Burp Suite. Ensure you have JPython loaded and setup
before installing.

You can modify the exclusion list by updating the strings on line 33.
Currently any strings that include the included words will not be analysed.

```
# Needed params

JSExclusionList = ['jquery', 'google-analytics','gpt.js']

```

## Usage

Once you've loaded the plugin there is some things to consider.
Burp performs threading on passive scanning by itself. This can be controlled by looking at the Scanner options.
For quick scanning I make use of the following settings with this plugin:

Scanner --> Live Scanning
 - Live Active Scanning : Disabled
 - Live Passive Scanning : Use suite scope
 
 As with ALL the burp scanner items, you have to give it a minute or so to work through the data. You shouldn't be waiting several minutes for a result tho.


##  Screenshot
![](https://i.imgur.com/KnmJrp1.gif)

## Update
- Added swing memory management 
- Added exclusion list on line 33 of code ['jquery', 'google-analytics','gpt.js']
