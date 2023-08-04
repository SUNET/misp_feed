#!/usr/bin/env python3

import time
from typing import Any, Dict, Optional

from pymisp.tools.abstractgenerator import AbstractMISPObjectGenerator


class SUNETC2MISPObject(AbstractMISPObjectGenerator):
    def __init__(
        self,
        dico_val: Dict[str, Any],
        tags: Dict[str, str],
        comments: Dict[str, str],
        to_ids: Dict[str, bool],
        disable_correlations: Dict[str, bool],
        **kargs: Any
    ):
        self._dico_val = dico_val
        self._tags = tags
        self._comments = comments
        self._to_ids = to_ids
        self._disable_correlations = disable_correlations

        #  Enforce attribute date with timestamp
        super(SUNETC2MISPObject, self).__init__("sunet-c2", **kargs)

        self.generate_attributes()

    def generate_attributes(self) -> None:
        if self._definition is None:
            raise ValueError("Problem with definition")

        valid_object_attributes = self._definition["attributes"].keys()

        for object_relation, value in self._dico_val.items():
            if isinstance(value, dict):
                self.add_attribute(
                    object_relation,
                    **value,
                    Tag=self._tags.get(object_relation),
                    to_ids=self._to_ids.get(object_relation),
                    comments=self._comments.get(object_relation),
                    disable_correlations=self._disable_correlations.get(object_relation)
                )
            else:
                # In this case, we need a valid template, as all the other parameters will be pre-set.
                self.add_attribute(
                    object_relation,
                    value=value,
                    Tag=self._tags.get(object_relation),
                    to_ids=self._to_ids.get(object_relation),
                    comments=self._comments.get(object_relation),
                    disable_correlations=self._disable_correlations.get(object_relation),
                )

    # def generate_attributes(self):
    #     #print(self._dico_val)
    #     valid_object_attributes = self._definition['attributes'].keys()
    #     for object_relation, value in self._dico_val.items():
    #     #    if object_relation not in valid_object_attributes:
    #     #        continue

    #         if object_relation == 'timestamp':
    #             # Date already in ISO format, removing trailing Z
    #             value = value.rstrip('Z')

    #         if isinstance(value, dict):
    #             self.add_attribute(object_relation, **value)
    #         else:
    #             # uniformize value, sometimes empty array
    #             if isinstance(value, list) and len(value) == 0:
    #                 value = ''
    #             self.add_attribute(object_relation, value=value)
