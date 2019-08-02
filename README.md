##  Disclaimer
I take not responsibility for your use of the software. Development is done in my personal capacity and carry no affiliation to my work.

#  BurpJSLinkFinder - Find links within JS files.
Burp Extension for a passive scanning JS files for endpoint links. 
 - Export results the text file
 - Exclude specific 'js' files e.g. jquery, google-analytics
 
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
 
 If the links have been excluded monitor the OUTPUT of the extension under the Extender options to verify.


##  Screenshot
![](https://i.imgur.com/KnmJrp1.gif)

## Update
- Added swing memory management  (14/06/2019)
- Added exclusion list on line 33 of code ['jquery', 'google-analytics','gpt.js'] (14/06/2019)
- Added ability to export files (15/06/2019)
