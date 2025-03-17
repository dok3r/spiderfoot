import json
import requests
from spiderfoot import SpiderFootEvent, SpiderFootPlugin

class sfp_hudsonrock(SpiderFootPlugin):

    meta = {
        'name': "Hudsonrock",
        'summary': "Queries Hudsonrock API for information on emails and domains.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Leaks, Dumps and Breaches"]
    }

    opts = {
        'api_key': ''
    }

    optdescs = {
        'api_key': "Hudsonrock API key. Leave empty for limited free access."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.opts.update(userOpts)

    def watchedEvents(self):
        return ["EMAILADDR", "DOMAIN_NAME"]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "PASSWORD_COMPROMISED", "EMAILADDR_COMPROMISED", "DOMAIN_NAME", "ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED"]

    def query_email(self, email):
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"
        headers = {}
        if self.opts['api_key']:
            headers['Authorization'] = f'Bearer {self.opts["api_key"]}'
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            return res.json()
        else:
            self.sf.error(f"Failed to fetch data from Hudsonrock API for email {email}: {res.status_code}")
            return None

    def query_domain(self, domain):
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}"
        headers = {}
        if self.opts['api_key']:
            headers['Authorization'] = f'Bearer {self.opts["api_key"]}'
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            return res.json()
        else:
            self.sf.error(f"Failed to fetch data from Hudsonrock API for domain {domain}: {res.status_code}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if eventName == "EMAILADDR":
            data = self.query_email(eventData)
            if data:
                evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
                self.notifyListeners(evt)
                if 'stealers' in data:
                    for stealer in data['stealers']:
                        evt = SpiderFootEvent("EMAILADDR_COMPROMISED", json.dumps(stealer), self.__name__, event)
                        self.notifyListeners(evt)

        if eventName == "DOMAIN_NAME":
            data = self.query_domain(eventData)
            if data:
                evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
                self.notifyListeners(evt)
                if 'data' in data and 'all_urls' in data['data']:
                    for url_info in data['data']['all_urls']:
                        evt = SpiderFootEvent("ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED", json.dumps(url_info), self.__name__, event)
                        self.notifyListeners(evt)

# End of sfp_hudsonrock class

