from ds_store import DSStore, DSStoreEntry

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IExtensionStateListener
from burp import IScanIssue

import StringIO
from urlparse import urlparse

def traverse_ds_store_file(d):
    """
    Traverse a DSStore object from the node and yeld each entry.
    :param d: DSStore object
    :return: None
    """
    node = d._rootnode
    with d._get_block(node) as block:
        next_node, count = block.read(b'>II')
        if next_node:
            for n in range(count):
                ptr = block.read(b'>I')[0]
                for e in d._traverse(ptr):
                    yield e
                e = DSStoreEntry.read(block)
                yield e
            for e in d._traverse(next_node):
                yield e
        else:
            for n in range(count):
                e = DSStoreEntry.read(block)
                yield e


def get_ds_store_content(ds_store_file):
    """
    List all entries from a .DS_Store file
    :param ds_store_file: .DS_Store file path
    :return: Set containing all files/directories found in the .DS_Store file
    """
    with DSStore.open(ds_store_file) as d:
        ds_store_content = set()
        for x in traverse_ds_store_file(d):
            if x.filename != '.':
                ds_store_content.add(x.filename)
    return ds_store_content


class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        """
        Implement IBurpExtender
        :param callbacks:
        :return:
        """
        # Callbacks object
        self._callbacks = callbacks
        # Set extension name
        callbacks.setExtensionName(".DS_Store Scanner")

        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)

        # Helpers object
        self._helpers = callbacks.getHelpers()
        return


    def doPassiveScan(self, baseRequestResponse):
        """
        Burp Scanner invokes this method for each base request/response that is
        passively scanned
        :param baseRequestResponse:
        :return: A list of scan issues (if any), otherwise None
        """
        self._requestResponse = baseRequestResponse

        scan_issues = self.findDSStoreFiles()
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    def doActiveScan(self):
        """
        Just so the scanner doesn't return a "method not implemented error"
        :return: None
        """
        return None

    def findDSStoreFiles(self):
        self._helpers = self._callbacks.getHelpers()
        self.scan_issues = []

        request = self._requestResponse.getRequest()
        path = request.tostring().split()[1]
        folder = path.rsplit("/", 1)

        # it's a folder
        if path.split("?")[0][-1] == "/":
            # TODO test to see if there's a .DS_Store file in that folder
            pass
        # it's a file
        else:
            filename = path.split("/")[-1].split("?")[0]
            # it's a .DS_Store file
            if filename == ".DS_Store":
                host = self._requestResponse.getHttpService().getHost()
                protocol = self._requestResponse.getHttpService().getProtocol()
                response = self._requestResponse.getResponse()
                responseInfo = self._helpers.analyzeResponse(response)
                bodyOffset = responseInfo.getBodyOffset()

                ds_store_file = StringIO.StringIO()
                ds_store_file.write(response.tostring()[bodyOffset:])
                ds_store_content = get_ds_store_content(ds_store_file)

                issuename = "Found .DS_Store file"
                issuelevel = "Low"
                issuedetail = """<p>The .DS_Store file contained the following entries: <br><ul><li>%s</li></ul></p>""" %\
                              "</li><li>".join(str(x) for x in ds_store_content)
                issueremediation = """Some remediation"""

                # Create a ScanIssue object and append it to our list of issues
                self.scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                                                  self._helpers.analyzeRequest(
                                                      self._requestResponse).getUrl(),
                                                  issuename,
                                                  issuelevel,
                                                  issuedetail,
                                                  issueremediation))

                # TODO add entries for each file found
                for content in ds_store_content:
                    content_url = protocol + '://' + host
                    print content_url


            # self._callbacks.addToSiteMap(requestResponse)

        return (self.scan_issues)

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getUrl() == newIssue.getUrl() and \
                        existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
        else:
            return 0

    def extensionUnloaded(self):
        print(".DS_Store Scanner Unloaded")
        return


# Implementation of the IScanIssue interface with simple constructor and getter methods
class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, name, severity, detailmsg, remediationmsg):
        self._url = url
        self._httpservice = httpservice
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg
        self._remediationmsg = remediationmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return None

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return self._remediationmsg

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"
