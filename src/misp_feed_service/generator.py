#!/usr/bin/env python3

import datetime
import hashlib
import json
import os
import sys
import time

import redis
from pymisp import MISPEvent, MISPOrganisation

from . import settings


def get_system_templates():
    """Fetch all MISP-Object template present on the local system.

    Returns:
        dict: A dictionary listing all MISP-Object templates

    """
    misp_objects_path = os.path.join(
        os.path.abspath(os.path.dirname(sys.modules["pymisp"].__file__)), "data", "misp-objects", "objects"
    )

    templates = {}

    for root, dirs, files in os.walk(misp_objects_path, topdown=False):
        for def_file in files:
            obj_name = root.split("/")[-1]
            template_path = os.path.join(root, def_file)
            with open(template_path, "r") as f:
                definition = json.load(f)
                templates[obj_name] = definition
    return templates


class FeedGenerator:
    """Helper object to create MISP feed.

    Configuration taken from the file settings.py"""

    def __init__(self):
        """This object can be use to easily create a daily MISP-feed.

        It handles the event creation, manifest file and cache file
        (hashes.csv).

        """

        self.redis_conn = redis.Redis(host=settings.host, port=settings.port, db=settings.db, decode_responses=True)
        if not self.redis_conn.ping():
            print("Could not connect to redis")
            sys.exit(1)

        self.sys_templates = get_system_templates()
        self.constructor_dict = settings.constructor_dict

        self.flushing_interval = settings.flushing_interval
        self.flushing_next = time.time() + self.flushing_interval

        self.manifest = {}
        self.attributeHashes = []

        self.daily_event_name = settings.daily_event_name + " {}"
        event_date_str, self.current_event_uuid, self.event_name = self.get_last_event_from_manifest()
        temp = [int(x) for x in event_date_str.split("-")]
        self.current_event_date = datetime.date(temp[0], temp[1], temp[2])
        self.current_event = self._get_event_from_id(self.current_event_uuid)

    def add_sighting_on_attribute(self, sight_type, attr_uuid, **data):
        """Add a sighting on an attribute.

        Not supported for the moment."""
        self.update_daily_event_id()
        self._after_addition()
        return False

    def add_attribute_to_event(self, attr_type, attr_value, **attr_data):
        """Add an attribute to the daily event"""
        self.update_daily_event_id()
        self.current_event.add_attribute(attr_type, attr_value, **attr_data)
        self._add_hash(attr_type, attr_value)
        self._after_addition()
        return True

    def add_object_to_event(self, obj_name, tags=None, comments=None, to_ids=None, disable_correlations=None, **data):
        """Add an object to the daily event"""
        self.update_daily_event_id()
        if obj_name not in self.sys_templates:
            print("Unkown object template")
            return False

        #  Get MISP object constructor
        obj_constr = self.constructor_dict.get(obj_name, None)
        #  Constructor not known, using the generic one
        if obj_constr is None:
            obj_constr = self.constructor_dict.get("generic")

        misp_object = obj_constr(data, tags, comments, to_ids, disable_correlations)

        #  Fill generic object
        for k, v in data.items():
            new_attribute = {"value": v}
            tag = None

            if tags is not None:
                for (
                    key,
                    value,
                ) in tags.items():
                    if k == key:
                        tag = value

            if comments is not None:
                for (
                    key,
                    value,
                ) in comments.items():
                    if k == key:
                        new_attribute["comment"] = value

            if to_ids is not None:
                for (
                    key,
                    value,
                ) in to_ids.items():
                    if k == key:
                        new_attribute["to_ids"] = value

            if disable_correlations is not None:
                for (
                    key,
                    value,
                ) in disable_correlations.items():
                    if k == key:
                        new_attribute["disable_correlation"] = value

            # attribute is not in the object template definition
            if k not in self.sys_templates[obj_name]["attributes"]:
                # add it with type text
                misp_object.add_attribute(k, **new_attribute)
            else:
                misp_object.add_attribute(k, **new_attribute, Tag=tag)

        else:
            misp_object = obj_constr(data, tags, comments, to_ids, disable_correlations)

        # print(misp_object.to_json())
        # sys.exit(1)

        self.current_event.add_object(misp_object)
        for attr_type, attr_value in data.items():
            self._add_hash(attr_type, attr_value)

        self._after_addition()
        return True

    def _after_addition(self):
        """Write event on disk"""
        self.current_event.timestamp = time.time()
        self.manifest.update(self.current_event.manifest)
        self.save_manifest()

        now = time.time()
        if self.flushing_next <= now:
            self.flush_event()
            self.flushing_next = now + self.flushing_interval

    # Cache
    def _add_hash(self, attr_type, attr_value):
        if "|" in attr_type or attr_type == "malware-sample":
            split = attr_value.split("|")
            self.attributeHashes.append(
                [hashlib.md5(str(split[0]).encode("utf-8"), usedforsecurity=False).hexdigest(), self.current_event_uuid]
            )
            self.attributeHashes.append(
                [hashlib.md5(str(split[1]).encode("utf-8"), usedforsecurity=False).hexdigest(), self.current_event_uuid]
            )
        else:
            self.attributeHashes.append(
                [
                    hashlib.md5(str(attr_value).encode("utf-8"), usedforsecurity=False).hexdigest(),
                    self.current_event_uuid,
                ]
            )

    # Manifest
    def _init_manifest(self):
        self.redis_conn.set(settings.manifest_key, json.dumps({}))

        # check if outputdir exists and try to create it if not
        # if not os.path.exists(settings.outputdir):
        #     try:
        #         os.makedirs(settings.outputdir)
        #     except PermissionError as error:
        #         print(error)
        #         print("Please fix the above error and try again.")
        #         sys.exit(126)

        # # create an empty manifest
        # try:
        #     with open(os.path.join(settings.outputdir, 'manifest.json'), 'w') as f:
        #         json.dump({}, f)
        # except PermissionError as error:
        #     print(error)
        #     print("Please fix the above error and try again.")
        #     sys.exit(126)

        # create new event and save manifest
        self.create_daily_event()

    def flush_event(self, new_event=None):
        print("Writing event on disk" + " " * 50)
        if new_event is not None:
            event_uuid = new_event["uuid"]
            event = new_event
        else:
            event_uuid = self.current_event_uuid
            event = self.current_event

        # with open(os.path.join(settings.outputdir, event_uuid + '.json'), 'w') as eventFile:
        #     json.dump(event.to_feed(), eventFile)

        self.redis_conn.set(f"{settings.event_prefix_key}{event_uuid}", json.dumps(event.to_feed()))

        self.save_hashes()

    def save_manifest(self):
        self.redis_conn.set(settings.manifest_key, json.dumps(self.manifest))

        # try:
        #     manifestFile = open(os.path.join(settings.outputdir, 'manifest.json'), 'w')
        #     manifestFile.write(json.dumps(self.manifest))
        #     manifestFile.close()
        #     print('Manifest saved')
        # except Exception as e:
        #     print(e)
        #     sys.exit('Could not create the manifest file.')

    def save_hashes(self):
        hashes_list = ""

        if len(self.attributeHashes) == 0:
            return False

        for element in self.attributeHashes:
            hashes_list += f"{element[0]},{element[1]}\n"

        self.redis_conn.rpush(settings.hashes_key, hashes_list)

        # try:
        #     hashFile = open(os.path.join(settings.outputdir, 'hashes.csv'), 'a')
        #     for element in self.attributeHashes:
        #         hashFile.write('{},{}\n'.format(element[0], element[1]))
        #         hashes_list = hashes_list + f"{element[0]},{element[1]}\n"
        #     hashFile.close()
        #     self.attributeHashes = []
        #     print('Hash saved' + ' ' * 30)
        # except Exception as e:
        #     print(e)
        #     sys.exit('Could not create the quick hash lookup file.')

    def get_last_event_from_manifest(self):
        """Retreive last event from the manifest
        .
                If the manifest doesn't  exists or if it is empty, initialize it.

        """
        redis_manifest = self.redis_conn.get(settings.manifest_key)
        if redis_manifest is None:
            self._init_manifest()
            return self.get_last_event_from_manifest()
        else:
            man_redis = json.loads(redis_manifest)
            dated_events_redis = []
            for event_uuid_redis, event_json_redis in man_redis.items():
                # add events to manifest
                self.manifest[event_uuid_redis] = event_json_redis
                dated_events_redis.append([event_json_redis["date"], event_uuid_redis, event_json_redis["info"]])
            # Sort by date then by event name
            dated_events_redis.sort(key=lambda k_redis: (k_redis[0], k_redis[2]), reverse=True)
            return dated_events_redis[0]

        # try:
        #     manifest_path = os.path.join(settings.outputdir, 'manifest.json')
        #     with open(manifest_path, 'r') as f:
        #         man = json.load(f)
        #         dated_events = []
        #         for event_uuid, event_json in man.items():
        #             # add events to manifest
        #             self.manifest[event_uuid] = event_json
        #             dated_events.append([
        #                 event_json['date'],
        #                 event_uuid,
        #                 event_json['info']
        #             ])
        #         # Sort by date then by event name
        #         dated_events.sort(key=lambda k: (k[0], k[2]), reverse=True)
        #         print("dated_events")
        #         print(dated_events[0])
        #         return dated_events[0]
        # except FileNotFoundError:
        #     print('Manifest not found, generating a fresh one')
        #     self._init_manifest()
        #     return self.get_last_event_from_manifest()

    # DAILY
    def update_daily_event_id(self):
        if self.current_event_date != datetime.date.today():  # create new event
            # save current event on disk
            self.flush_event()
            self.current_event = self.create_daily_event()
            self.current_event_date = datetime.date.today()
            self.current_event_uuid = self.current_event.get("uuid")
            self.event_name = self.current_event.info

    def _get_event_from_id(self, event_uuid):
        redis_event = self.redis_conn.get(f"{settings.event_prefix_key}{event_uuid}")
        # print(redis_event)
        event_dict = json.loads(redis_event)
        if event_dict["Event"]["uuid"] == event_uuid:
            event = MISPEvent()
            event.from_dict(**event_dict["Event"])
            return event
        raise ValueError("Could not find event from id in db")

        # with open(os.path.join(settings.outputdir, '%s.json' % event_uuid), 'r') as f:
        #     event_dict = json.load(f)['Event']
        #     event = MISPEvent()
        #     event.from_dict(**event_dict)
        #     return event

    def create_daily_event(self):
        today = str(datetime.date.today())
        event_dict = {
            "id": len(self.manifest) + 1,
            "Tag": settings.Tag,
            "info": self.daily_event_name.format(today),
            "analysis": settings.analysis,  # [0-2]
            "threat_level_id": settings.threat_level_id,  # [1-4]
            "published": settings.published,
            "date": today,
        }
        event = MISPEvent()
        event.from_dict(**event_dict)

        # reference org
        org = MISPOrganisation()
        org.name = settings.org_name
        org.uuid = settings.org_uuid
        event.Orgc = org

        # save event on disk
        self.flush_event(new_event=event)
        # add event to manifest
        self.manifest.update(event.manifest)
        self.save_manifest()
        return event
