#
#  BurpLinkFinder - Find links within JS files.
#
#  Copyright (c) 2022 Frans Hendrik Botes
#  Credit to https://github.com/GerbenJavado/LinkFinder for the idea and regex
#
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
import cgi
from os import path
from javax import swing
from java.awt import Font, Color
from threading import Thread
#from array import array
from jarray import array
from java.awt import EventQueue
from java.lang import Runnable
from thread import start_new_thread
from javax.swing import JFileChooser
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing.event import DocumentListener
from javax.swing import JCheckBox
from javax.swing import SwingUtilities
from javax.swing import JTextField
from javax.swing.table import AbstractTableModel
import urlparse,threading
try: 
    import queue
except ImportError:
    import Queue as queue

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# Needed params
JSExclusionList = ['jquery', 'google-analytics','gpt.js','modernizr','gtm','fbevents']

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpJSLinkFinderv2")
        callbacks.issueAlert("BurpJSLinkFinderv2 Passive Scanner enabled")
        #stdout = PrintWriter(callbacks.getStdout(), True)
        #stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        self.threads = []
        self.initUI()
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(self._splitpane2)
        callbacks.customizeUiComponent(self.logPane)
        callbacks.customizeUiComponent(self.filesPane)
        callbacks.customizeUiComponent(self.mapPane)
        callbacks.customizeUiComponent(self._parentPane)
        callbacks.customizeUiComponent(self._parentPane)
        callbacks.customizeUiComponent(self._parentPane)
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        callbacks.printOutput("BurpJS LinkFinder v2 loaded.")
        callbacks.printOutput("Copyright (c) 2022 Frans Hendrik Botes")
        self.outputTxtArea.setText("BurpJS LinkFinder loaded." + "\n" + "Copyright (c) 2022 Frans Hendrik Botes" + "\n")

    def initUI(self):
        self._parentPane = JTabbedPane()
        # The main split pane for the components
        self._splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._splitpane.setDividerLocation(800)
        # The split pane for the mapping and filenames
        self._splitpane2 = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane2.setDividerLocation(300)
        # UI for Log Output
        self.logPanel = swing.JPanel()
        self.outputLabel = swing.JLabel("LinkFinder Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 12))
        self.outputLabel.setForeground(Color(255,102,52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 10))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export", actionPerformed=self.exportLog)
        self.parentFrm = swing.JFileChooser()
        # Layout
        layout = swing.GroupLayout(self.logPanel)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.logPanel.setLayout(layout)
      
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )
        layout.setVerticalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )

        # UI for Filenames Pane
        self.filePanel = swing.JPanel()
        self.fileNamesLabel = swing.JLabel("Filenames:")
        self.fileNamesLabel.setFont(Font("Tahoma", Font.BOLD, 12))
        self.fileNamesLabel.setForeground(Color(255,102,52))
        self.filesPane = swing.JScrollPane()
        self.filesTxtArea = swing.JTextArea()
        self.filesTxtArea.setFont(Font("Consolas", Font.PLAIN, 10))
        self.filesTxtArea.setLineWrap(True)
        self.filesPane.setViewportView(self.filesTxtArea)
        self.clearFilesBtn = swing.JButton("Clear", actionPerformed=self.clearFilseLog)

        # Layout
        layoutf = swing.GroupLayout(self.filePanel)
        layoutf.setAutoCreateGaps(True)
        layoutf.setAutoCreateContainerGaps(True)
        self.filePanel.setLayout(layoutf)
      
        layoutf.setHorizontalGroup(
            layoutf.createParallelGroup()
            .addGroup(layoutf.createSequentialGroup()
                .addGroup(layoutf.createParallelGroup()
                    .addComponent(self.fileNamesLabel)
                    .addComponent(self.filesPane)
                    .addComponent(self.clearFilesBtn)
                )
            )
        )
        layoutf.setVerticalGroup(
            layoutf.createParallelGroup()
            .addGroup(layoutf.createParallelGroup()
                .addGroup(layoutf.createSequentialGroup()
                    .addComponent(self.fileNamesLabel)
                    .addComponent(self.filesPane)
                    .addComponent(self.clearFilesBtn)
                )
            )
        )

        # UI for Mapped Pane
        self.mapPanel = swing.JPanel()
        self.mapLabel = swing.JLabel("Mapped:")
        self.mapLabel.setFont(Font("Tahoma", Font.BOLD, 12))
        self.mapLabel.setForeground(Color(255,102,52))
        self.mapPane = swing.JScrollPane()
        self.mapTxtArea = swing.JTextArea()
        self.mapTxtArea.setFont(Font("Consolas", Font.PLAIN, 10))
        self.mapTxtArea.setLineWrap(True)
        self.mapPane.setViewportView(self.mapTxtArea)
        self.clearMapBtn = swing.JButton("Clear", actionPerformed=self.clearMAPLog)
        self.mapMapBtn = swing.JButton("Map", actionPerformed=self.mapMaps)
        # Layout
        layoutm = swing.GroupLayout(self.mapPanel)
        layoutm.setAutoCreateGaps(True)
        layoutm.setAutoCreateContainerGaps(True)
        self.mapPanel.setLayout(layoutm)
      
        layoutm.setHorizontalGroup(
            layoutm.createParallelGroup()
            .addGroup(layoutm.createSequentialGroup()
                .addGroup(layoutm.createParallelGroup()
                    .addComponent(self.mapLabel)
                    .addComponent(self.mapPane)
                    .addComponent(self.clearMapBtn)
                    .addComponent(self.mapMapBtn)                   
                )
            )
        )
        layoutm.setVerticalGroup(
            layoutm.createParallelGroup()
            .addGroup(layoutm.createParallelGroup()
                .addGroup(layoutm.createSequentialGroup()
                    .addComponent(self.mapLabel)
                    .addComponent(self.mapPane)
                    .addComponent(self.clearMapBtn)
                    .addComponent(self.mapMapBtn)
                )
            )
        )

        #Set up all the panes
        self._splitpane.setLeftComponent(self.logPanel)
        self._splitpane2.setTopComponent(self.filePanel)
        self._splitpane2.setBottomComponent(self.mapPanel)
        self._splitpane.setRightComponent(self._splitpane2)
        self._parentPane.addTab("Main", self._splitpane)
    def getTabCaption(self):
        return "BurpJSLinkFinder"
    def getUiComponent(self):
        return self._parentPane
    def clearLog(self, event):
          self.outputTxtArea.setText("BurpJS LinkFinder loaded." + "\n" + "Copyright (c) 2022 Frans Hendrik Botes" + "\n" )
    def clearFilseLog(self, event):
          self.filesTxtArea.setText("")
    def clearMAPLog(self, event):
          self.mapTxtArea.setText("")      
    def exportLog(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        self.callbacks.printOutput("\n" + "Export to : " + filename)
        open(filename, 'w', 0).write(self.outputTxtArea.text)
    def doPassiveScan(self, ihrr):      
        try:
            urlReq = ihrr.getUrl()
            testString = str(urlReq)
            linkA = linkAnalyse(ihrr,self.callbacks,self.helpers)
            # check if JS file
            if ".js" in str(urlReq):
                # Exclude casual JS files
                if any(x in testString for x in JSExclusionList):
                    self.callbacks.printOutput("\n" + "[-] URL excluded " + str(urlReq))
                else:
                    self.outputTxtArea.append("\n" + "[+] Valid URL found: " + str(urlReq))
                    issueText = linkA.analyseURL()
                    links = []
                    full_urls = []
                    highlights = []
                    for counter, issueText in enumerate(issueText):
                            self.outputTxtArea.append("\n" + "\t" + issueText['link'])
                            if linkA.valcheckFullURL(issueText['link']) and linkA.valcheckMappedList(issueText['link'],self.mapTxtArea):
                                self.mapTxtArea.append("\n" + issueText['link'])
                                full_urls += [issueText['link']]
                            elif not linkA.valcheckFullURL(issueText['link']):
                                fullURL = urlparse.urljoin(urlparse.urljoin(str(urlReq), '/'),issueText['link'])
                                if linkA.valcheckMappedList(fullURL,self.mapTxtArea):
                                    self.mapTxtArea.append("\n" + fullURL)
                                full_urls += [fullURL]
                            
                            lh = [issueText['start'],issueText['end']]
                            if issueText['link'] not in links:
                                links += [issueText['link']]
                            if lh not in highlights:
                                highlights += [lh]
                            
                            filNam = os.path.basename(issueText['link'])
                            if linkA.isNotBlank((filNam)):
                                try:
                                    filNam = filNam[ 0 : filNam.index("?")]
                                except:
                                    filNam = filNam

                                if (linkA.checkValidFile(filNam)) and (filNam not in self.filesTxtArea.text):
                                    self.filesTxtArea.append("\n" + filNam)
                            
                    issues = ArrayList()
                    if links != []:
                        issues.add(SRI(ihrr, self.helpers, self.callbacks, links, full_urls, highlights))
                    return issues
        except UnicodeEncodeError:
            self.callbacks.printOutput("Error in URL decode.")
        return None
    def consolidateDuplicateIssues(self, isb, isa):
        return -1
    def extensionUnloaded(self):
        self.callbacks.printOutput("BurpJS LinkFinder v2 unloaded")
        return

    def mapMaps(self,event):
        self.q = queue.Queue()
        get_all_urls = self.mapTxtArea.getText()
        urls_list = list(set(get_all_urls.split('\n')))

        for url in urls_list:
            url = url.rstrip()
            self.q.put(url)

        for j in range(10):
            t = threading.Thread(target=self.ProcessQueue)
            self.threads.append(t)
            t.start()

    def ProcessQueue(self):
        while not self.q.empty():
            each_url = self.q.get()
            self.ProcessURL(each_url)
            self.q.task_done()
            self.mapTxtArea.setText("")        

    def URL_SPLITTER(self,url):
        URL_SPLIT = str(url).split("://",1)
        URL_PROTOCAL = URL_SPLIT[0]
        if URL_PROTOCAL == 'https':
            URL_PORT = 443
        elif URL_PROTOCAL == 'http':
            URL_PORT = 80
        else:
            URL_PORT = 443
        URL_HOSTNAME = URL_SPLIT[1].split('/',1)[0].split('?',1)[0]
        if ':' in URL_HOSTNAME:
            URL_HOSTNAME_FOR_SPLIT = URL_HOSTNAME
            URL_HOSTNAME = URL_HOSTNAME_FOR_SPLIT.split(':')[0]
            URL_PORT = int(URL_HOSTNAME_FOR_SPLIT.split(':')[1])
        URL_HOST_FULL = URL_PROTOCAL+"://"+URL_HOSTNAME
        try:
            URL_HOST_SERVICE = self.helpers.buildHttpService(URL_HOSTNAME,URL_PORT,URL_PROTOCAL)
        except java.lang.IllegalArgumentException:
            self.callbacks.printOutput("EXCEPTION BECAUSE HTTPSERVICE VALUES IS INVALID : {} : ".format(url))
            self.callbacks.printOutput("EXCEPTION VALUES ARE :",URL_HOSTNAME,URL_PORT,URL_PROTOCAL)
        return URL_SPLIT,URL_PROTOCAL,URL_HOSTNAME,URL_PORT,URL_HOST_FULL,URL_HOST_SERVICE

    def ProcessURL(self,url):
        #print(url)
        if url.startswith('http://') or url.startswith('https://'):
            URL_SPLIT,URL_PROTOCAL,URL_HOSTNAME,URL_PORT,URL_HOST_FULL,URL_HOST_SERVICE = self.URL_SPLITTER(url)
            try:
                HEADERS = ["GET /"+str(URL_SPLIT[1].split('/',1)[1])+" HTTP/1.1",'Host: '+str(URL_HOSTNAME)]
            except:
                novar = 1
                #print("URL EXCEPTION IN HEADERS : {} : {}".format(url,URL_SPLIT))
            msg = self.helpers.buildHttpMessage(HEADERS,None)
            resp = self.callbacks.makeHttpRequest(URL_HOST_SERVICE,msg)
            if resp.getResponse() != None:
                resp_analyze = self.helpers.analyzeResponse(resp.getResponse())
                self.callbacks.addToSiteMap(resp)
                resp_heads = resp_analyze.getHeaders()
                if '301' in resp_heads[0] or 'Moved' in resp_heads[1] or '307' in resp_heads[0] or '302' in resp_heads[0]:
                    for each_head in resp_heads:
                        if each_head.startswith('Location:') or each_head.startswith('location:'):
                            location_value = each_head.split(":",1)[1].strip(' ')
                            if location_value.startswith('http'):
                                URL_SPLIT,URL_PROTOCAL,URL_HOSTNAME,URL_PORT,URL_HOST_FULL,URL_HOST_SERVICE = self.URL_SPLITTER(location_value)
                                try:
                                    HEADERS = ["GET /"+str(URL_SPLIT[1].split('/',1)[1])+" HTTP/1.1",'Host: '+str(URL_HOSTNAME)]
                                except:
                                    #print("URL EXCEPTION IN REDIRECTION HEADERS : {}".format(URL_SPLIT))
                                    return False
                                if self.HEADERS:
                                    for each_header in self.HEADERS:
                                        if each_header not in HEADERS:
                                            HEADERS.append(each_header)
                            elif location_value.startswith('/'):
                                HEADERS = ["GET "+str(location_value)+" HTTP/1.1",'Host: '+str(URL_HOSTNAME)]
                                if self.HEADERS:
                                    for each_header in self.HEADERS:
                                        if each_header not in HEADERS:
                                            HEADERS.append(each_header)
                            else:
                                pass
                            msg = self.helpers.buildHttpMessage(HEADERS,None)
                            resp = self.callbacks.makeHttpRequest(URL_HOST_SERVICE,msg)            
                            self.callbacks.addToSiteMap(resp)

class linkAnalyse():
    
    def __init__(self, reqres, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.reqres = reqres
        

    regex_str = """
    
      (?:"|')                               # Start newline delimiter
    
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    
        |
    
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be
    
        |
    
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/.]{1,}                # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
    
        |

        ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
        [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
        (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

        |
    
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)        # . + extension
        (?:\?[^"|']{0,}|))                  # ? mark with parameters
    
      )
    
      (?:"|')                               # End newline delimiter
    
    """     

    def parser_file(self, content, regex_str, mode=1, more_regex=None, no_dup=1):
        #print ("TEST parselfile #2")
        regex = re.compile(regex_str, re.VERBOSE)
        items = [{"link": m.group(1),"start":m.start(1),"end":m.end(1)} for m in re.finditer(regex, content)]
        if no_dup:
            # Remove duplication
            all_links = set()
            no_dup_items = []
            for item in items:
                if item["link"] not in all_links:
                    all_links.add(item["link"])
                    no_dup_items.append(item)
            items = no_dup_items
    
        # Match Regex
        filtered_items = []
        for item in items:
            # Remove other capture groups from regex results
            if more_regex:
                if re.search(more_regex, item["link"]):
                    #print ("TEST parselfile #3")
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
        return filtered_items
    # Potential for use in the future...
    def threadAnalysis(self):
        thread = Thread(target=self.analyseURL(), args=(session,))
        thread.daemon = True
        thread.start()

    def analyseURL(self):      
        endpoints = ""
        mime_type=self.helpers.analyzeResponse(self.reqres.getResponse()).getStatedMimeType()
        if mime_type.lower() == 'script':
                url = self.reqres.getUrl()
                encoded_resp=binascii.b2a_base64(self.reqres.getResponse())
                decoded_resp=base64.b64decode(encoded_resp)
                endpoints=self.parser_file(decoded_resp, self.regex_str)
                return endpoints
        return endpoints

    def checkValidFile(self,fileNam):
        regexFile = """^[a-zA-Z0-9](?:[a-zA-Z0-9 ._-]*[a-zA-Z0-9])?.[a-zA-Z0-9_-][.].*"""
        try:
            if fileNam and fileNam.strip():
                return bool(re.search(regexFile, fileNam))
            
        except:


            return False
       
    def isNotBlank(self,myString):
        try:
            if myString and myString.strip():
                #myString is not None AND myString is not empty or blank
                return True
            #myString is None OR myString is empty or blank
        except:
            return False

    def valcheckMappedList(self,myString,mapTxtArea):
        #Checks if the extracted URL is a full URL or if already in the mapped list
        #print("Checking URL: " + myString)
        try:
            if (myString in mapTxtArea.text):
                #print("Found HTTP in URL: " + myString)
                return False
            
        except Exception as e:
            self.callbacks.printOutput(myString + "\t" + str(e))
            return True
        
        #print("Returning Default: " + myString)
        return True
    
    def valcheckFullURL(self,myString):
        try:
            if (myString[:4].lower() == 'http'):
                return True
        except Exception as e:
            self.callbacks.printOutput(myString + "\t" + str(e))
        return False

class SRI(IScanIssue,ITab):
    def __init__(self, reqres, helpers, callbacks, links, full_urls, highlights):
        self.helpers = helpers
        self.callbacks = callbacks
        
        self.links = links
        self.links.sort()
        self.full_urls = full_urls
        self.full_urls.sort()

        al = ArrayList()
        i=0
        while i<len(highlights):
            al.add(array([highlights[i][0],highlights[i][1]],'i'))
            i+=1
        self.highlights = al
        self.reqres = self.callbacks.applyMarkers(reqres,None,self.highlights)
        
        self.issue_detail = "Burp Scanner has analysed this JS file and has discovered the following link values: <ul>\n"
        i=0
        while i<len(self.links):
            self.issue_detail += "<li>{}</li>\n".format(cgi.escape(self.links[i]))
            i+=1
        self.issue_detail += "</ul>The following full normalized URLs were generated from the discovered link values: <ul>\n"
        i=0
        while i<len(self.full_urls):
            self.issue_detail += "<li>{}</li>\n".format(cgi.escape(self.full_urls[i]))
            i+=1
        self.issue_detail = str(self.issue_detail)

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Linkfinder Analysed JS files"

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Certain"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("JS files holds links to other parts of web applications. Refer to TAB for results.")

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self.issue_detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        #print ("................raising issue................")
        rra = [self.reqres]
        return rra
        
    def getHttpService(self):
        return self.reqres.getHttpService()
        
        
if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
