#  BurpJSLinkFinder - Find links within JS files.
![Follow on Twitter](https://img.shields.io/twitter/follow/frans_initroot?label=Follow%20&style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/initroot/BurpJSLinkFinder)
![GitHub stars](https://img.shields.io/github/stars/initroot/BurpJSLinkFinder)


Burp Extension for a passive scanning JS files for endpoint links. 
 - Export results the text file
 - Exclude specific 'js' files e.g. jquery, google-analytics
 
Copyright (c) 2022 Frans Hendrik Botes


Credit to https://github.com/GerbenJavado/LinkFinder for the idea and regex

##  Disclaimer
I take not responsibility for your use of the software. Development is done in my personal capacity and carry no affiliation to my work.

## Setup
For use with the professional version of Burp Suite. Ensure you have JPython loaded and setup
before installing.

You can modify the exclusion list by updating the strings on line 50.
Currently any strings that include the included words will not be analysed.

```
# Needed params

JSExclusionList = ['jquery', 'google-analytics','gpt.js','modernizr','gtm','fbevents']

```

## Usage
Instructions based on the most recent versions of Burp. The following configurations are advised:
- Set target scope under Target --> Scope --> Advance scope --> Keyword
- Set scanners to only scan scoped items e.g. Dashboard --> Live scanner and Live audit set URL Scope to Suite Scope

##  Screenshot
![Screen Recording 2021-12-31 at 10 43 36](https://user-images.githubusercontent.com/954507/147813394-50564827-d017-446d-8bdc-b21022da2114.gif)

## Update
- Added swing memory management  (14/06/2019)
- Added exclusion list on line 33 of code ['jquery', 'google-analytics','gpt.js'] (14/06/2019)
- Added ability to export files (15/06/2019)
- Added filename extracter pane (31/12/2021)
- Added URL mapper, very basic at this time (31/12/2021)
- Minor cosmetic changes on the log for quicker copy paste (31/12/2021)
