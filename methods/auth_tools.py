#!/usr/bin/python3
# coding=utf-8
# pylint: disable=R0903,C0116

#   Copyright 2025 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Method """

# from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import web  # pylint: disable=E0611,E0401

# from tools import context  # pylint: disable=E0401
from tools import auth  # pylint: disable=E0401


class Method:
    """ Method """

    @web.method()
    def check_credential_data(self, source, credential_type, credential_data):
        if credential_type not in auth.credential_handlers:
            raise ValueError("No credential handler")
        #
        try:
            auth_type, auth_id, auth_reference = \
                auth.credential_handlers[credential_type](
                    source, credential_data
                )
        except BaseException as exc:  # pylint: disable=W0702
            raise ValueError("Bad credential") from exc
        #
        return auth.access_success_reply(
            source, auth_type, auth_id, auth_reference, to_json=True
        )

    @web.method()
    def check_authorization_header(self, source, auth_header):
        if " " not in auth_header:
            raise ValueError("Invalid auth header")
        #
        credential_type, credential_data = auth_header.split(" ", 1)
        credential_type = credential_type.lower()
        #
        return self.check_credential_data(source, credential_type, credential_data)
