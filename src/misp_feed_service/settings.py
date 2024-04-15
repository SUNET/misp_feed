# import os

""" REDIS RELATED """
# Your redis server
host = "redis"
port = 6379
db = 0

manifest_key = "misp_c2_manifest"
event_list_key = "misp_c2_event_list"
event_prefix_key = "misp_c2_event_prefix_"
hashes_key = "misp_c2_hashes"

## The keynames to POP element from
keyname_pop = ["sunet-c2"]

# OTHERS
## If key prefix not provided, data will be added as either object, attribute or sighting
fallback_MISP_type = "object"
### How to handle the fallback
fallback_object_template_name = "sunet-c2"  # MISP-Object only
fallback_attribute_category = "comment"  # MISP-Attribute only

## How frequent the event should be written on disk
flushing_interval = 5 * 60
## The redis list keyname in which to put items that generated an error
keyname_error = "feed-generation-error"

""" FEED GENERATOR CONFIGURATION """

# The output dir for the feed. This will drop a lot of files, so make
# sure that you use a directory dedicated to the feed
outputdir = "output"

# Event meta data
## Required
### The organisation id that generated this feed
org_name = "SUNET_C2-scanner"
### Your organisation UUID
org_uuid = ""
### The daily event name to be used in MISP.
### (e.g. honeypot_1, will produce each day an event of the form honeypot_1 dd-mm-yyyy)
daily_event_name = "SUNET_C2_daily"

## Optional
analysis = 2
threat_level_id = 1
published = True
Tag = [
    {"colour": "#fcc000", "name": "tlp:amber"},
    {"colour": "#ffc000", "name": 'PAP:AMBER'},
    {"colour": "#ff5c00", "name": "SUNET:C2-scanner-feed"},
]

from pymisp.tools import GenericObjectGenerator

# MISP Object constructor
# from ObjectConstructor.CowrieMISPObject import CowrieMISPObject
from .SUNETC2MISPObject import SUNETC2MISPObject

constructor_dict = {"sunet-c2": SUNETC2MISPObject, "generic": GenericObjectGenerator}

# Others
## Redis pooling time
sleep = 60
