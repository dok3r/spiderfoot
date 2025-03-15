import json
# from wappalyzer import analyze
# import spiderfoot
import wappalyzer
from spiderfoot import SpiderFootEvent, SpiderFootPlugin

class sfp_wappalyzer_next(SpiderFootPlugin):
    meta = {
        "name": "Wappalyzer Next",
        "summary": "Identify technologies used by a website using Wappalyzer.",
        "flags": ["web"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Content Analysis"],
    }
    opts = {}  # Define options (even if empty)
    optdescs = {}  # Define configuration options (leave empty if none)

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.opts = userOpts if userOpts else {}  # Ensure opts is not empty

    def watchedEvents(self):
        return ["DOMAIN_NAME", "IP_ADDRESS", "WEBSERVER_BANNER", "WEBSITE_CONTENT"]

    def producedEvents(self):
        return ["WEBSERVER_TECHNOLOGY"]

    def extract_technologies(self, target):
        try:
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"  # Default to HTTPS

            results = wappalyzer.analyze(url=target, scan_type='full', threads=3)
            if target in results:
                return [(tech, results[target][tech].get("version", "")) for tech in results[target].keys()]
            return []
        except Exception as e:
            self.error(f"Failed to run Wappalyzer: {e}")
            return []

    def handleEvent(self, event):
        if event.eventType not in self.watchedEvents():
            return
        
        target = event.data
        self.debug(f"Analyzing target with Wappalyzer: {target}")
        
        technologies = self.extract_technologies(target)
        if not technologies:
            return
        
        for tech, version in technologies:
            tech_info = f"{tech} (Version: {version})" if version else tech
            evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", tech_info, self.__name__, event)
            self.notifyListeners(evt)


