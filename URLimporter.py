from burp import IBurpExtender,ITab
from javax.swing import JPanel,JLabel,SwingConstants,JButton,JTextArea,JScrollPane
from java.net import URL
from java.awt import Font,FlowLayout
import threading,queue
import java

class BurpExtender(IBurpExtender,ITab):
    THREAD_NUM = 20
    def registerExtenderCallbacks(self,callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("URLIMPORTER")
        self.threads = []

        self.__initLayout__()
        self.callbacks.addSuiteTab(self)

    def __initLayout__(self):
        self.panel = JPanel()
        self.panel.setLayout(FlowLayout())
        self.panel.setBounds(40,80,200,200)
        self.UI_URLS_AREA = JTextArea('',14,80)
        self.UI_URLS_AREA.setLineWrap(True)
        self.UI_URLS_AREA_SCROLL = JScrollPane(self.UI_URLS_AREA)

        self.UI_HEADERS = JTextArea('',8,50)
        self.UI_HEADERS.setLineWrap(True)
        self.UI_HEADERS_AREA_SCROLL = JScrollPane(self.UI_HEADERS)

        self.url_add_to_sitemap_button = JButton("ADD TO SITEMAP",actionPerformed=self.URLS_ADD_TO_SITEMAP)

        self.UI_HEADERS.setText("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36")
        self.panel.add(self.url_add_to_sitemap_button)
        self.panel.add(self.UI_URLS_AREA_SCROLL)
        self.panel.add(self.UI_HEADERS_AREA_SCROLL)

    def getTabCaption(self):
        return "CimexURLImport"

    def getUiComponent(self):
        return self.panel

    def URLS_ADD_TO_SITEMAP(self,event):
        self.q = queue.Queue()
        get_all_urls = self.UI_URLS_AREA.getText()
        get_headers = self.UI_HEADERS.getText()
        self.HEADERS = list(set(get_headers.split('\n')))
        urls_list = list(set(get_all_urls.split('\n')))

        for url in urls_list:
            url = url.rstrip()
            self.q.put(url)

        for j in range(self.THREAD_NUM):
            t = threading.Thread(target=self.ProcessQueue)
            self.threads.append(t)
            t.start()

    def ProcessQueue(self):
        while not self.q.empty():
            each_url = self.q.get()
            self.ProcessURL(each_url)
            self.q.task_done()

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
            print("EXCEPTION BECAUSE HTTPSERVICE VALUES IS INVALID : {} : ".format(url))
            print("EXCEPTION VALUES ARE :",URL_HOSTNAME,URL_PORT,URL_PROTOCAL)
        return URL_SPLIT,URL_PROTOCAL,URL_HOSTNAME,URL_PORT,URL_HOST_FULL,URL_HOST_SERVICE

    def ProcessURL(self,url):
        print(url)
        if url.startswith('http://') or url.startswith('https://'):
            URL_SPLIT,URL_PROTOCAL,URL_HOSTNAME,URL_PORT,URL_HOST_FULL,URL_HOST_SERVICE = self.URL_SPLITTER(url)
            try:
                HEADERS = ["GET /"+str(URL_SPLIT[1].split('/',1)[1])+" HTTP/1.1",'Host: '+str(URL_HOSTNAME)]
            except:
                print("URL EXCEPTION IN HEADERS : {} : {}".format(url,URL_SPLIT))
            if self.HEADERS:
                for each_header in self.HEADERS:
                    if each_header not in HEADERS:
                        HEADERS.append(each_header)
            msg = self.helpers.buildHttpMessage(HEADERS,None)
            resp = self.callbacks.makeHttpRequest(URL_HOST_SERVICE,msg)
            if resp.getResponse() != None:
                resp_analyze = self.helpers.analyzeResponse(resp.getResponse())
                self.callbacks.addToSiteMap(resp) ###! Adding Redirecting Request too in sitemap....
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
                                    print("URL EXCEPTION IN REDIRECTION HEADERS : {}".format(URL_SPLIT))
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
