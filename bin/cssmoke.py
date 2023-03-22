#!/usr/bin/env python

import sys
import os
import requests as req
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)

def attach_resp_to_event(event, data):
    event["ip_range_score"] = data["ip_range_score"]
    event["ip"] = data["ip"]
    event["ip_range"] = data["ip_range"]
    event["as_name"] = data["as_name"]
    event["as_num"] = data["as_num"]

    event["country"] = data["location"]["country"]
    event["city"] = data["location"]["city"]
    event["latitude"] = data["location"]["latitude"]
    event["longitude"] = data["location"]["longitude"]
    event["reverse_dns"] = data["reverse_dns"]

    event["behaviors"] = data["behaviors"]

    event["first_seen"] = data["history"]["first_seen"]
    event["last_seen"] = data["history"]["last_seen"]
    event["full_age"] = data["history"]["full_age"]
    event["days_age"] = data["history"]["days_age"]

    event["false_positives"] = data["classifications"]["false_positives"]
    event["classifications"] = data["classifications"]["classifications"]

    # attack_details
    event["attack_details"] = data["attack_details"]

    # target_countries
    event["target_countries"] = data["target_countries"]

    # background_noise_score
    event["background_noise_score"] = data["background_noise_score"]

    # overall
    event["overall_aggresiveness"] = data["scores"]["overall"]["aggressiveness"]
    event["overall_threat"] = data["scores"]["overall"]["threat"]
    event["overall_trust"] = data["scores"]["overall"]["trust"]
    event["overall_anomaly"] = data["scores"]["overall"]["anomaly"]
    event["overall_total"] = data["scores"]["overall"]["total"]

    # last_day
    event["last_day_aggresiveness"] = data["scores"]["last_day"]["aggressiveness"]
    event["last_day_threat"] = data["scores"]["last_day"]["threat"]
    event["last_day_trust"] = data["scores"]["last_day"]["trust"]
    event["last_day_anomaly"] = data["scores"]["last_day"]["anomaly"]
    event["last_day_total"] = data["scores"]["last_day"]["total"]

    # last_week
    event["last_week_aggressiveness"] = data["scores"]["last_week"]["aggressiveness"]
    event["last_week_threat"] = data["scores"]["last_week"]["threat"]
    event["last_week_trust"] = data["scores"]["last_week"]["trust"]
    event["last_week_anomaly"] = data["scores"]["last_week"]["anomaly"]
    event["last_week_total"] = data["scores"]["last_week"]["total"]

    # last_month
    event["last_month_aggressiveness"] = data["scores"]["last_month"][
        "aggressiveness"
    ]
    event["last_month_threat"] = data["scores"]["last_month"]["threat"]
    event["last_month_trust"] = data["scores"]["last_month"]["trust"]
    event["last_month_anomaly"] = data["scores"]["last_month"]["anomaly"]
    event["last_month_total"] = data["scores"]["last_month"]["total"]
    # references
    event["references"] = data["references"]
    return event


@Configuration()
class CsSmokeCommand(StreamingCommand):

    """%(synopsis)

    ##Syntax

    %(syntax)

    ##Description

    %(description)

    """

    ipfield = Option(
        doc="""
        **Syntax:** **ipfield=***<fieldname>*
        **Description:** Name of the IP address field to look up""",
        require=True,
        validate=validators.Fieldname(),
    )

    def stream(self, events):
        api_key = ""
        for passw in self.service.storage_passwords.list():
            if passw.name == "crowdsec-splunk-app_realm:api_key:":
                api_key = passw.clear_password
                break
        if not api_key:
            raise Exception("No API Key found, please configure the app with CrowdSec CTI API Key")

        # API required headers
        headers = {
            "x-api-key": api_key,
            "Accept": "application/json",
            "User-Agent": "crowdSec-splunk-app/v1.0.0",
        }

        for event in events:
            event_dest_ip = event[self.ipfield]
            # API required parameters
            params = (
                ("ipAddress", event_dest_ip),
                ("verbose", ""),
            )
            # Make API Request
            error = 0
            response = req.get(
                f"https://cti.api.crowdsec.net/v2/smoke/{event_dest_ip}",
                headers=headers,
                params=params,
            )
            if response.status_code == 200:
                data = response.json()
                event = attach_resp_to_event(event, data)
            elif response.status_code == 429:
                event["error"] = '"Quota exceeded for CrowdSec CTI API. Please visit https://www.crowdsec.net/pricing to upgrade your plan."'
            else:
                event["error"] = f"Error {response.status_code} : {response.text}"

            # Finalize event
            yield event


dispatch(CsSmokeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
