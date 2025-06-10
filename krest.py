#
# (c) 2015 Kaminario Technologies, Ltd.
#
# This software is licensed solely under the terms of the Apache 2.0 license,
# the text of which is available at http://www.apache.org/licenses/LICENSE-2.0.
# All disclaimers and limitations of liability set forth in the Apache 2.0 license apply.
#

from __future__ import absolute_import

__version__ = "1.3.6"

import json
try:  # Python2
    from urlparse import urljoin
    from urllib import urlencode
except ImportError:  # Python3
    from urllib.parse import urlencode, urljoin
from functools import wraps
import logging
import traceback
from collections import UserDict

import requests
from requests.exceptions import ConnectionError, HTTPError, Timeout
from requests.auth import HTTPBasicAuth, AuthBase
import time

logger = logging.getLogger("krest")

user_tags_discovered_TEMPORARY_FLAG_UNTIL_API_VERSION_INCREASED_FOR_USER_TAGS = False
api_version = 0
def api_supports_user_tags_feature():
    return user_tags_discovered_TEMPORARY_FLAG_UNTIL_API_VERSION_INCREASED_FOR_USER_TAGS or (api_version == "3.0.7")

class KrestProtocolError(Exception):
    def __init__(self, message, response):
        super(KrestProtocolError, self).__init__(message)
        self.response = response

class KRestJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (RestObject, RestObjectProxy)):
            return o._ref
        return super(KRestJSONEncoder, self).default(o)


class NoPasswordPrintDict(UserDict):
    PASSWORD_STR_LIST = ["password", "current_user_password", "new_password"]

    def __repr__(self):
        filtered_dict = {k: v if k not in self.PASSWORD_STR_LIST else "*" * len(v) for k, v in self.items()}
        return repr(filtered_dict)


def hide_password(data):
    try:
        if isinstance(data, dict):
            return NoPasswordPrintDict(data)
        if isinstance(data, list):
            return [NoPasswordPrintDict(bulk_dict) for bulk_dict in data]
    except ValueError:
        logger.warning("Unrecognized request data. can't hide password.")

    return data


class KrestBasicAuth(HTTPBasicAuth):
    pass


class KrestBearerAuth(AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r


class EndPoint(object):

    api_prefix = "/api/v2"

    class ReqCfg(object):
        pass

    class RetryCfg(object):
        not_reachable_timeout = 600
        not_reachable_pause = 20
        toofast_pause = .5

        on_connect_errors = True
        on_auth_required = False
        on_5xx_errors = True
        on_4xx_errors = False
        on_other_errors = True
        on_toofast_error = False

    def __init__(self, k2_addr, username=None, password=None, auth: AuthBase=None, sdp_id=None,
                 ssl_validate=True,
                 autodiscover=True,
                 lazy_load_references=True,
                 parse_references=True,
                 validate_endpoints=True,
                 ):

        # args validation:
        if isinstance(auth, KrestBearerAuth) and not sdp_id:
            raise ValueError("Can't use BearerAuth without sdp_id")
        if sdp_id and not isinstance(auth, KrestBearerAuth):
            raise ValueError("Invalid args, sdp_id can't run without KrestBearerAuth")
        if auth and (username or password):
            raise ValueError("Invalid args, Can't use both methods - Auth and username/password")
        if not autodiscover and validate_endpoints:
            raise ValueError("Invalid args, Can't use validate_endpoints without autodiscover")

        self.full_endpoint = "%s/%s" % (self.api_prefix, "__full")

        self.lazy_load_references = lazy_load_references
        self.parse_references = parse_references
        self.validate_endpoints = validate_endpoints
        self.ssl_validate = ssl_validate
        self.auth = auth if auth else KrestBasicAuth(username, password)

        self.base_url = "https://%s" % k2_addr
        if sdp_id:
            self.api_prefix = "/rest/sdps/%s%s" % (sdp_id, self.api_prefix)

        self.session = requests.Session()

        self.req_cfg = self.ReqCfg()
        self.retry_cfg = self.RetryCfg()

        if autodiscover:
            self.discover()

        api_version = getattr(self.get("system/state", 1), "rest_api_version", None)
        pass


    def exception_wrapper(func):
        @wraps(func)
        def wrapped(self, *args, **kwargs):
            start_time = time.time()
            retry = True
            retry_too_fast = False
            saved_exc = None
            while retry:
                retry = False
                try:
                    return func(self, *args, **kwargs)
                except (ConnectionError, Timeout) as err:
                    logger.error("Connection/Timeout Error: %s", str(err))
                    if self.retry_cfg.on_connect_errors:
                        retry = True
                    saved_exc = err
                except HTTPError as err:
                    err_str = str(err)
                    status_code = err.response.status_code
                    logger.error("HTTP Error: %s (response-status_code = %d)", err_str, status_code)
                    if 400 <= status_code and status_code <= 499:
                        if status_code == 401 and self.retry_cfg.on_auth_required:
                            logger.error("Authorization required - retrying as requested")
                            retry = True
                        if status_code == 429 and self.retry_cfg.on_toofast_error:
                            logger.error("Server says we are going too fast. Slowing down")
                            retry_too_fast = True
                        elif self.retry_cfg.on_4xx_errors:
                            logger.error("Managed error - retrying as requested...")
                            retry = True
                        else:
                            logger.error("Managed error - not retrying...")
                    elif 500 <= status_code and status_code <= 599:
                        if self.retry_cfg.on_5xx_errors:
                            logger.error("Unmanaged error - Going to retry...")
                            retry = True
                    elif self.retry_cfg.on_other_errors:
                        logger.error("Unknown error - Going to retry...")
                        retry = True
                    saved_exc = err
                except Exception as err:
                    logger.error("Caught unexpected error of type %s: %s", type(err), str(err))
                    logger.error("The traceback is:\n%s", traceback.format_exc())
                    retry = False
                    saved_exc = err
                if retry and time.time() - start_time < self.retry_cfg.not_reachable_timeout:
                    logger.error("Sleeping for %s seconds", self.retry_cfg.not_reachable_pause)
                    time.sleep(self.retry_cfg.not_reachable_pause)
                    logger.error("Retrying")
                elif retry_too_fast:
                    time.sleep(self.retry_cfg.toofast_pause)
                    retry = True
                else:
                    if isinstance(saved_exc, HTTPError):
                        raise self._rebuild_err(saved_exc)
                    else:
                        raise saved_exc
        return wrapped

    def _rebuild_err(self, exception):
        response = exception.response
        if response.headers["content-type"] == "application/json":
            data = response.json()
            msg = data.get("error_msg", None) or data
        else:
            msg = response.text
        e = HTTPError("%s\n%s" % (str(exception), msg))
        e.response = response
        return e

    def _prepare_request_data(self, req_args):
        if "data" in req_args:
            data = req_args["data"]
            if data is not None:
                req_args["data"] = json.dumps(data, cls=KRestJSONEncoder)
                logger.info("Request data: %s" % hide_password(data))
            else:
                del req_args["data"]

    def _prepare_request_headers(self, req_args, options):
        headers = {'content-type': 'application/json'}
        if hasattr(self.req_cfg, "headers"):
            headers.update(self.req_cfg.headers)
        if "headers" in req_args:
            headers.update(req_args["headers"])

        req_args.update(self.req_cfg.__dict__)
        # Taking out "headers" field from req_args - we pass it explicitly
        if "headers" in req_args:
            del req_args["headers"]

        sequence = options.get("sequence", {})
        if sequence:
            headers["X-K2-Sequence"] = []
            for id, num in sequence.items():
                headers["X-K2-Sequence"].append("%s=%s" % (id, num))
            headers["X-K2-Sequence"] = ",".join(headers["X-K2-Sequence"])

        return headers

    def _prepare_request_timeout(self, req_args, req_options):
        if "timeout" in req_args:
            return
        if "timeout" in req_options:
            req_args["timeout"] = req_options["timeout"]
            return
        if hasattr(self.req_cfg, "timeout"):
            req_args["timeout"] = self.req_cfg.timeout
            return

    # noinspection PyArgumentList
    @exception_wrapper
    def _request(self, method, endpoint, options={}, **kwargs):
        logger.info("Method: %s - Sending: %s" % (str(method), str(endpoint)))

        self._prepare_request_timeout(kwargs, options)
        self._prepare_request_data(kwargs)
        headers = self._prepare_request_headers(kwargs, options)

        raw = options.get("raw", False)
        kwargs["stream"] = options.get("stream", True) if raw else options.get("stream", False)

        rv = self.session.request(method, endpoint, auth=self.auth, verify=self.ssl_validate, headers=headers, **kwargs)
        rv.raise_for_status()

        # WARNING: Evaluating value of rv.content will negate the effect of stream=True
        if not raw:
            if rv.content:
                rv = rv.json()
            elif method != "DELETE":
                raise KrestProtocolError("Received response without content", rv)
        logger.info("Returned value is: %s", rv)
        return rv

    def _resource_url(self, resource_type):
        if self.validate_endpoints:
            suffix = None
            if resource_type.endswith("__bulk") or resource_type.endswith("__meta"):
                resource_type, _, suffix = resource_type.rpartition("/")
            resource_path = self.resources[resource_type]
            if suffix:
                resource_path = "%s/%s" % (resource_path, suffix)
        else:
            resource_path = "/%s" % resource_type
        endpoint = self.api_prefix + resource_path
        return urljoin(self.base_url, endpoint)

    def _obj_ref(self, resource_type, id):
        return "%s/%s" % (self.resources[resource_type], id)

    def _obj_url(self, resource_type, id):
        return "%s/%s" % (self._resource_url(resource_type), id)

    def get(self, resource_type, id, options={}, **query):
        # query is passed merely for __fields support
        url = self._obj_url(resource_type, id)
        if query:
            self._serialize_query_objects(query)
            url += "?%s" % urlencode(query)

        rv = self._request("GET", url, options=options)
        if options.get("raw", False):
            return rv.text
        ro = RestObject(self, resource_type, **rv)
        return ro

    def post(self, ro, options={}):
        rv = self._request("POST", self._resource_url(ro._resource_type), data=ro._current, options=options)
        ro._update(**rv)
        return ro

    def patch(self, ro, options={}):
        if not ro._changed:
            return
        rv = self._request("PATCH", ro._obj_url, data=ro._changed, options=options)
        ro._update(**rv)
        return ro

    def patch_object_user_tags(self, parameters):
        self._request("PATCH", self._obj_url("user_tags",0), data=parameters)

    def delete(self, ro, options={}):
        data = ro._changed or None  # Don't send empty {} to server
        self._request("DELETE", ro._obj_url, data=data, options=options)

    def new(self, resource_type, bulk=False, meta=False, **attrs):
        if self.validate_endpoints and resource_type not in self.resources:
            raise ValueError("Unknown resource_type: %s" % resource_type)
        if bulk:
            if attrs:
                raise ValueError("attrs do not go together with bulk")
            return BulkRequest(self, resource_type, meta=meta)
        else:
            return RestObject.new(self, resource_type, meta=meta, **attrs)

    def discover(self, options={}):
        self.resources = dict()
        self.resource_endpoints = dict()
        data = self._request("GET", urljoin(self.base_url, self.api_prefix), options=options)
        for k, v in data["resources"].items():
            if k == "user_tags":
                global user_tags_discovered_TEMPORARY_FLAG_UNTIL_API_VERSION_INCREASED_FOR_USER_TAGS
                user_tags_discovered_TEMPORARY_FLAG_UNTIL_API_VERSION_INCREASED_FOR_USER_TAGS = True
            self.resources[k] = v["url"]
            self.resource_endpoints[v["url"]] = k

    def _serialize_query_objects(self, query):
        for k, v in list(query.items()):
            if isinstance(v, RestObjectBase):
                del query[k]
                k = k + ".ref"
                query[k] = v._obj_ref
                continue

            if isinstance(v, ResultSet):
                v = v.hits
            if isinstance(v, (list, tuple)):
                if k.endswith("__m_eq") or k.endswith("__in"):
                    # User wants to do stuff by himself
                    continue

                del query[k]
                if k != "__fields":  # Special case that does not require search modifier
                    k += ".ref__m_eq" if isinstance(v[0], RestObjectBase) else "__m_eq"
                query[k] = ",".join(_v._obj_ref if isinstance(_v, RestObjectBase) else _v for _v in v)
                continue

    def search(self, resource_type, options={}, **query):
        self._serialize_query_objects(query)
        url = self._resource_url(resource_type)
        url += "?%s" % urlencode(query)

        data = self._request("GET", url, options=options)
        if options.get("raw", False):
            if options.get("fp", None):
                return self.stream_response_to_file(data, options["fp"])
            return data

        rs = ResultSet(self, resource_type, data, query)
        return rs

    def dump_all(self, fp, pretty=False, read_chunk=8192):
        """Dumps all objects in raw JSON to a provided file descriptor"""
        url = urljoin(self.base_url, self.full_endpoint)
        if pretty:
            sep = "&" if "?" in url else "?"
            url = "%s%s__pretty" % (url, sep)
        r = self._request("GET", url, options={"raw": True})
        self.stream_response_to_file(r, fp, read_chunk)

    def stream_response_to_file(self, res, fp, read_chunk=8192):
        for chunk in res.iter_content(read_chunk):
            fp.write(chunk)


class RestObjectBase(object):
    def __repr__(self):
        return self.__str__()

    @property
    def _obj_ref(self):
        return self._ep._obj_ref(self._resource_type, self.id)

    @property
    def _obj_url(self):
        return self._ep._obj_url(self._resource_type, self.id)

    @property
    def _ref(self):
        return {"ref": self._obj_ref}


class ObjectUserModelTag(object):
    def __init__(self, taggable_object, tag_params):
        self._invalid = False
        self._taggable_object = taggable_object
        self.key = tag_params["key"]
        self.value = tag_params["value"]
        self.is_inheritable = tag_params["is_inheritable"]
        self.possession_type = tag_params["possession_type"] # Allows to know legal operations on the tag. In case of a new tag, will be None. It may not be OWNER, as this key was deleted before added again.
        self._is_automatic = tag_params["is_automatic"]

    def __str__(self):
        return "%s = %s" % (self.key, self.value)

    def __setattr__(self, attr, val):
        if (attr != "_invalid") and self._invalid:
            raise ValueError("This tag is no longer valid, as the object containing it - was stored. Please re-obtain the tag from the object.")
        super().__setattr__(attr, val)
        if attr != "_invalid":
            self._taggable_object.on_user_tags_change()
            return

    def remove(self):
        self._taggable_object._current["user_tags"].remove(self)
        self._taggable_object.on_user_tags_change()

    def replace_taggable_object(self, updated_taggable_object):
        self._taggable_object = updated_taggable_object


    def fill_tag_params(self, tags_list):
        tags_list.append({
            "key": self.key,
            "value": self.value,
            "is_inheritable": self.is_inheritable,
            "is_automatic": self._is_automatic
        })

    def _invalidate(self):
        self._invalid = True

class RestObjectProxy(RestObjectBase):
    def __init__(self, ep, ref):
        self._ep = ep
        (self._resource_endpoint, _, self.id) = ref["ref"].rpartition("/")
        self.id = int(self.id)
        self._resource_type = self._ep.resource_endpoints[self._resource_endpoint]

    def __call__(self):
        ro = self._ep.get(self._resource_type, self.id)
        return ro

    def __eq__(self, other, shallow=None):
        # "shallow" parameter is supported for compatibility -
        # proxies can only be compared in shallow mode
        if not isinstance(other, (RestObject, RestObjectProxy)):
            return False
        if self._resource_type != other._resource_type:
            return False
        if not hasattr(other, "id"):
            return False
        return self.id == other.id

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        return "<%s('%s') %s>" % (self.__class__.__name__, self._resource_type, self._ref)


class RestObject(RestObjectBase):
    def __init__(self, ep, resource_type, meta=False, **kwargs):
        self._ep = ep
        self._resource_type = resource_type
        if meta:
            self._resource_type = self._resource_type.rstrip("/") + "/__meta"
        self._update(**kwargs)

    def get_user_tags_object_type(self):
        if self._resource_type == "host_groups":
            return "host_group"
        elif self._resource_type == "hosts":
            return "host"
        elif self._resource_type == "volume_groups":
            return "volume_group"
        elif self._resource_type == "volumes":
            return "volume"
        elif self._resource_type == "replication_sessions":
            return "replication_session"
        elif self._resource_type == "snapshots":
            if self.is_exposable:
                return "view"
            else:
                return "snapshot"
        else:
            return None

    def supports_user_tags_feature(self):
        return api_supports_user_tags_feature() and (self.get_user_tags_object_type() is not None)

    @classmethod
    def new(cls, ep, resource_type, **kwargs):
        obj = cls(ep, resource_type, **kwargs)
        obj._changed = obj._current
        if obj.supports_user_tags_feature():
            obj._current["user_tags"] = list()
        return obj

    def save(self, options={}):
        user_tags_changed = self._user_tags_changed if self.supports_user_tags_feature() and hasattr(self, "id") else dict()
        if hasattr(self, "id"):
            # construct things that changed and run patch
            self._ep.patch(self, options=options)
        else:
            self._ep.post(self, options=options)
        if user_tags_changed:
            for user_tag in self._current["user_tags"]:
                user_tag._invalidate()
            self._ep.patch_object_user_tags(user_tags_changed)
            self.refresh()
        return self

    def delete(self, options={}):
        return self._ep.delete(self, options=options)

    def refresh(self, options={}):
        if not hasattr(self, "id"):
            return
        new_obj = self._ep.get(self._resource_type, self.id, options=options)
        self._update(**new_obj._current)

    def on_user_tags_change(self):
        self._user_tags_changed = {}
        self._user_tags_changed["action"] = "set_object_tags"
        self._user_tags_changed["object_type"] = self.get_user_tags_object_type()
        self._user_tags_changed["object_name"] = self.name
        self._user_tags_changed["is_validate_only"] = False
        self._user_tags_changed["tags"] = []
        for model_tag in self._current["user_tags"]:
            model_tag.fill_tag_params(self._user_tags_changed["tags"])

    def get_user_tag(self, tag_key):
        if not self.supports_user_tags_feature():
            raise NotImplementedError
        for user_tag in self._current["user_tags"]:
            if user_tag.key == tag_key:
                return user_tag
        return None

    def has_user_tag(self, tag_key):
        if not self.supports_user_tags_feature():
            raise NotImplementedError
        return self.get_user_tag(tag_key) is not None

    def add_user_tag(self, key, value, is_inheritable):
        if not self.supports_user_tags_feature():
            raise NotImplementedError
        if not hasattr(self, "id"):
            raise ValueError("Can't add a user tags to a new, non-stored object. Please store the object first.")
        self._current["user_tags"].append(ObjectUserModelTag(self, { "key": key, "value": value, "is_inheritable": is_inheritable, "is_automatic": False, "possession_type": None}))
        self.on_user_tags_change()

    def remove_user_tag(self, tag_key):
        if not self.supports_user_tags_feature():
            raise NotImplementedError
        self.get_user_tag(tag_key).remove()

    def modify_user_tag(self, tag_key, new_key=None, new_value=None, new_is_inheritable=None):
        if not self.supports_user_tags_feature():
            raise NotImplementedError
        user_tag = self.get_user_tag(tag_key)
        if new_key is not None:
            user_tag.key = new_key
        if new_value is not None:
            user_tag.value = new_value
        if new_is_inheritable is not None:
            user_tag.is_inheritable = new_is_inheritable

    def __setattr__(self, attr, val):
        if not attr.startswith("_"):
            if attr == "user_tags":
                if not self.supports_user_tags_feature():
                    raise NotImplementedError
                if val is not []:
                    raise ValueError("Can't set directly user_tags property. Please use add_user_tag method.")
            self._changed[attr] = self._current[attr] = val
            return
        super(RestObject, self).__setattr__(attr, val)

    def __getattr__(self, attr):
        if attr == "_current":  # Object state not initialized
            raise AttributeError(attr)
        if attr not in self._current:
            raise AttributeError(attr)
        val = self._current[attr]
        if self._ep.lazy_load_references and isinstance(val, RestObjectProxy):
            val = val()
            self._current[attr] = val
        return val

    def _update(self, **kwargs):
        self._current = dict()
        for k, v in kwargs.items():
            if k == "user_tags":
                # This is a taggable object
                self._current["user_tags"] = []
                for item in v:
                    if type(item) is ObjectUserModelTag:
                        item.replace_taggable_object(self)
                        self._current["user_tags"].append(item)
                    else:
                        self._current["user_tags"].append(ObjectUserModelTag(self, item))
            elif self._ep.parse_references and isinstance(v, list):
                self._current[k] = []
                for item in v:
                    if isinstance(item, dict) and "ref" in item:
                        self._current[k].append(RestObjectProxy(self._ep, item))
            elif self._ep.parse_references and isinstance(v, dict) and "ref" in v:
                self._current[k] = RestObjectProxy(self._ep, v)
            else:
                self._current[k] = v
        self._changed = dict()

        if self.supports_user_tags_feature():
            self._user_tags_changed = dict()

    def _get_raw(self, attr):
        return self._current[attr]

    def __str__(self):
        return "<%s('%s') %s>" % (self.__class__.__name__, self._resource_type, self._current)

    def __eq__(self, other, shallow=False):
        if not isinstance(other, (RestObject, RestObjectProxy)):
            return False

        if self._resource_type != other._resource_type:
            return False

        if shallow:
            if not hasattr(self, "id") or not hasattr(other, "id"):
                return False
            return self.id == other.id

        if set(self._current.keys()).symmetric_difference(other._current.keys()):
            return False

        for k, v in self._current.items():
            o_v = other._current[k]
            if isinstance(v, RestObject) or isinstance(o_v, RestObject):
                if not v.__eq__(o_v, shallow=True):
                    return False
            elif v != o_v:
                return False
        return True

    def __ne__(self, other):
        return not self == other


class ResultSet(object):
    """
    Simple object for working with results set.
    """
    def __init__(self, ep, resource_type, data, query, convert_to_rest_objects=True):
        if convert_to_rest_objects:
            self.hits = [RestObject(ep, resource_type, **hit) for hit in data["hits"]]
        else:
            self.hits = data["hits"]
        self.total = data["total"]
        self.limit = data.get("limit", len(self.hits))
        self.offset = data.get("offset", 0)
        self.autofetch = False
        self._resource_type = resource_type
        self._query = query
        self._ep = ep
        self._current_hit_index = 0

    def delete_all(self):
        for hit in self.hits:
            hit.delete()

    def __iter__(self):
        self._current_hit_index = 0
        return self

    def next(self):
        if self._current_hit_index == len(self.hits):
            if not self.autofetch or self._query is None:
                raise StopIteration
            self.next_chunk()
            if not self.hits:
                raise StopIteration
        rv = self.hits[self._current_hit_index]
        self._current_hit_index += 1
        return rv

    __next__ = next  # P3k

    def next_chunk(self):
        if "__offset" in self._query:
            self._query["__offset"] += self.limit
        else:
            self._query["__offset"] = self.limit
        rs = self._ep.search(self._resource_type, **self._query)
        af = self.autofetch
        self.__dict__.update(rs.__dict__)
        self.autofetch = af

    def __nonzero__(self):
        return bool(self.hits)

    def __len__(self):
        return self.total


class BulkRequest(object):
    def __init__(self, ep, resource_type, meta=False):
        self._ep = ep
        self._resource_type = resource_type
        self._suffix = "/__meta" if meta else "/__bulk"
        self._items = list()

    def add(self, item):
        assert isinstance(item, (RestObject, ResultSet))
        if item._resource_type != self._resource_type:
            raise ValueError("%s object found. Expected %s" % (item._resource_type, self._resource_type))
        if isinstance(item, RestObject):
            self._items.append(item)
        else:  # ResultSet
            self._items.extend(item.hits)

    def post(self, options={}):
        data = self._request("POST", options=options)
        return self._to_resultset(data)

    def patch(self, options={}):
        data = self._request("PATCH", options=options)
        return self._to_resultset(data)

    def delete(self, options={}):
        self._request("DELETE", options=options)

    def _to_resultset(self, data):
        return ResultSet(self._ep, self._resource_type, data, query=None)

    def _request(self, method, options={}):
        resource_url = self._ep._resource_url(self._resource_type) + self._suffix
        data = [i._current for i in self._items]
        return self._ep._request(method, resource_url, data=data, options=options)

    def __iter__(self):
        for item in self._items:
            yield item

    def __len__(self):
        return len(self._items)
