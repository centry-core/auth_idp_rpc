#!/usr/bin/python3
# coding=utf-8

#   Copyright 2023 getcarrier.io
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

""" RPC """

import datetime

# from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import web  # pylint: disable=E0611,E0401

# from tools import context  # pylint: disable=E0401
from tools import auth  # pylint: disable=E0401


class RPC:  # pylint: disable=E1101,R0903
    """ RPC Resource """

    @web.rpc("auth_authorize")
    def authorize(self, source, headers, cookies):  # pylint: disable=R0911,R0914
        """ Auth endpoint """
        # Check auth header
        if "Authorization" in headers:
            auth_header = headers.get("Authorization")
            if " " not in auth_header:
                # Invalid auth header
                return auth.access_denied_reply(source, to_json=True)
            #
            credential_type, credential_data = auth_header.split(" ", 1)
            credential_type = credential_type.lower()
            #
            if credential_type not in auth.credential_handlers:
                # No credential handler
                return auth.access_denied_reply(source, to_json=True)
            #
            try:
                auth_type, auth_id, auth_reference = \
                    auth.credential_handlers[credential_type](
                        source, credential_data
                    )
            except:  # pylint: disable=W0702
                # Bad credential
                return auth.access_denied_reply(source, to_json=True)
            #
            return auth.access_success_reply(
                source, auth_type, auth_id, auth_reference, to_json=True
            )
        # Check other auth headers
        other_auth_headers = self.descriptor.config.get(
            "other_auth_headers", {}
        )
        for header_name, credential_type in  other_auth_headers.items():
            if header_name in headers:
                credential_data = headers.get(header_name)
                #
                if credential_type not in auth.credential_handlers:
                    # No credential handler
                    return auth.access_denied_reply(source, to_json=True)
                #
                try:
                    auth_type, auth_id, auth_reference = \
                        auth.credential_handlers[credential_type](
                            source, credential_data
                        )
                except:  # pylint: disable=W0702
                    # Bad credential
                    return auth.access_denied_reply(source, to_json=True)
                #
                return auth.access_success_reply(
                    source, auth_type, auth_id, auth_reference, to_json=True
                )
        # NB: Public rules check is also done in main pylon auth proxy-plugin
        is_public_route = False
        for rule in auth.public_rules:
            if auth._public_rule_matches(rule, source):  # pylint: disable=W0212
                # Public request
                is_public_route = True
        # Browser auth
        session_cookie_name = self.context.app.session_cookie_name
        if session_cookie_name not in cookies:
            # Is public?
            if is_public_route:
                return auth.access_success_reply(source, "public", to_json=True)
            # Never visited auth
            target_token = auth.sign_target_url(auth.make_source_url(source))
            return auth.access_needed_redirect(target_token, to_json=True)
        #
        auth_reference = cookies.get(session_cookie_name)
        auth_ctx = auth.get_referenced_auth_context(auth_reference)
        if auth_ctx["done"] and \
                (
                        auth_ctx["expiration"] is None or
                        datetime.datetime.now() < auth_ctx["expiration"]
                ):
            # Auth done
            return auth.access_success_reply(
                source,
                auth_type="user",
                auth_id=str(auth_ctx["user_id"]) \
                    if auth_ctx["user_id"] is not None else "-",
                auth_reference=auth_reference,
                to_json=True,
            )
        # NB: Public rules check is also done in main pylon auth proxy-plugin
        if is_public_route:
            # Public request
            return auth.access_success_reply(source, "public", to_json=True)
        # Auth needed or expired
        auth.set_referenced_auth_context(auth_reference, {})
        target_token = auth.sign_target_url(auth.make_source_url(source))
        return auth.access_needed_redirect(target_token, to_json=True)
