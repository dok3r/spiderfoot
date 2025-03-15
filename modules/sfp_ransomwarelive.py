# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ransomwarelive
# Purpose:     SpiderFoot module to query Ransomware.live API v2/searchvictims/<keyword> endpoint.
#
# Author:      kost
#
# Copyright:   (c) kost 2025
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse
from spiderfoot import SpiderFootEvent, SpiderFootPlugin

class sfp_ransomwarelive(SpiderFootPlugin):
    meta = {
        'name': "Ransomware.live Search",
        'summary': "Queries Ransomware.live API v2/searchvictims/<keyword> to search for ransomware victims.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://www.ransomware.live/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': ["https://www.ransomware.live/api"],
            'description': "Searches ransomware victims using the Ransomware.live API."
        }
    }

    opts = {
        'max_retries': 3,
        'initial_backoff': 5
    }
    optdescs = {
        'max_retries': "Maximum number of retries when rate limit (429) is encountered.",
        'initial_backoff': "Initial backoff time (seconds) before retrying after a rate limit."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.rate_limited = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "COMPANY_NAME"]

    def producedEvents(self):
        return ["MALICIOUS_AFFILIATE_INTERNET_NAME", "AFFILIATE_DOMAIN_NAME", "RAW_RIR_DATA", "GEOINFO"]

    def queryRansomwareLive(self, keyword):
        url = f"https://api.ransomware.live/v2/searchvictims/{urllib.parse.quote(keyword)}"
        headers = {'Accept': 'application/json'}

        retries = 0
        while retries < self.opts['max_retries']:
            try:
                res = self.sf.fetchUrl(
                    url,
                    timeout=10,
                    useragent="SpiderFoot"
                )

                if res['code'] == "429":
                    self.error("Rate limit exceeded by Ransomware.live API.")
                    backoff = self.opts['initial_backoff'] * (2 ** retries)
                    self.info(f"Backing off for {backoff} seconds due to rate limit.")
                    time.sleep(backoff)
                    retries += 1
                    continue

                if res['code'] not in ["200", "404"] or res['content'] is None:
                    self.error(f"Unexpected response from Ransomware.live API (code: {res['code']}, content: {res['content']})")
                    return None

                try:
                    data = json.loads(res['content']) if res['content'] else []
                except json.JSONDecodeError as e:
                    self.error(f"Error decoding JSON from Ransomware.live API: {str(e)}, raw content: {res['content']}")
                    return None

                if not isinstance(data, list):
                    self.error(f"Expected a list from API, got {type(data)}: {data}")
                    return None

                return data

            except Exception as e:
                self.error(f"Error querying Ransomware.live API: {str(e)}")
                return None

        self.error(f"Max retries ({self.opts['max_retries']}) exceeded for rate limit.")
        self.rate_limited = True
        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.rate_limited:
            self.debug("Skipping event due to persistent rate limiting.")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True
        self.debug(f"Received event, {eventName}, from {srcModuleName}: {eventData}")

        data = self.queryRansomwareLive(eventData)
        if not data:
            return

        for victim in data:
            if not isinstance(victim, dict):
                self.error(f"Expected a dictionary for victim, got {type(victim)}: {victim}")
                continue

            victim_name = victim.get('victim', '').lower()
            victim_domain = victim.get('domain', '').lower() if victim.get('domain') else None
            group_name = victim.get('group', 'Unknown')
            discovered_date = victim.get('discovered', 'Unknown')
            attack_date = victim.get('attackdate', 'Unknown')
            country = victim.get('country', 'Unknown')
            description = victim.get('description', '')
            claim_url = victim.get('claim_url', '') if victim.get('claim_url') else 'Not provided'

            target_lower = eventData.lower()
            is_match = False
            if (eventName == "DOMAIN_NAME" and victim_domain and target_lower in victim_domain) or \
               (eventName == "COMPANY_NAME" and victim_name and target_lower in victim_name):
                is_match = True

            if is_match:
                evt_text = (f"Ransomware victim: {victim_name} (Domain: {victim_domain}, "
                           f"Group: {group_name}, Attack: {attack_date}, Discovered: {discovered_date}, "
                           f"Country: {country}, Claim URL: {claim_url}) - {description}")
                evt = SpiderFootEvent("MALICIOUS_AFFILIATE_INTERNET_NAME", evt_text, self.__name__, event)
                self.notifyListeners(evt)

                if victim_domain:
                    domain_evt = SpiderFootEvent("AFFILIATE_DOMAIN_NAME", victim_domain, self.__name__, event)
                    self.notifyListeners(domain_evt)

                if country != "Unknown":
                    geo_evt = SpiderFootEvent("GEOINFO", f"{victim_name} located in {country}", self.__name__, event)
                    self.notifyListeners(geo_evt)

                if claim_url and claim_url != "Not provided":
                    leak_evt = SpiderFootEvent("RAW_RIR_DATA", f"Ransomware claim URL for {victim_name}: {claim_url}", self.__name__, event)
                    self.notifyListeners(leak_evt)

                raw_evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(victim), self.__name__, event)
                self.notifyListeners(raw_evt)


