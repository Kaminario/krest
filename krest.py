from __future__ import absolute_import

__version__ = "1.0.9"

import json
import urlparse
import urllib
from functools import wraps
import logging

import requests
from requests.exceptions import ConnectionError, HTTPError
import time

# Enabling logging in your krest application
# import krest
#import logging
#logging.addHandler(km_log_handler)
#logging.getLogger("krest").setLevel(logging.DEBUG)
#logging.getLogger("request").setLevel(logging.DEBUG)

#TODO: Parse errors properly
#TODO: Don't retry on Bad Request errors


class KRestJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, RestObject):
            return o._ref
        return super(KRestJSONEncoder, self).default(o)


logger = logging.getLogger("krest")


class EndPoint(object):

    api_prefix = "/api/v2"

    class ReqCfg(object):
        pass

    class RetryCfg(object):
        connect_errors = True
        http_errors = False
        not_reachable_timeout = 600
        not_reachable_pause = 20

    def __init__(self, k2_addr, username, password, ssl_validate=True, autodiscover=True):
        self.full_endpoint = "%s/%s" % (self.api_prefix, "__full")

        self.ssl_validate = ssl_validate
        self.base_url = "https://%s" % k2_addr
        self.auth = (username, password)
        self.session = requests.Session()

        self.req_cfg = self.ReqCfg()
        self.retry_cfg = self.RetryCfg()

        if autodiscover:
            self.discover()

    def exception_wrapper(func):
        @wraps(func)
        def wrapped(self, *args, **kwargs):
            start_time = time.time()
            retry = True
            while retry and time.time() - start_time < self.retry_cfg.not_reachable_timeout:
                retry = False
                try:
                    return func(self, *args, **kwargs)
                except ConnectionError, err:
                    logger.error("Connection Error: %s", str(err))
                    if self.retry_cfg.connect_errors:
                        retry = True
                except HTTPError, err:
                    logger.error("HTTP Error: %s", str(err))
                    if self.retry_cfg.http_errors:
                        retry = True
                except Exception, err:
                    logger.error("Error: %s", str(err))
                if retry:
                    logger.error("Sleeping for %s seconds", self.retry_cfg.not_reachable_pause)
                    time.sleep(self.retry_cfg.not_reachable_pause)
                    logger.error("Retrying")
                else:
                    raise err
        return wrapped

    #noinspection PyArgumentList
    @exception_wrapper
    def _request(self, method, endpoint, **kwargs):
        if "data" in kwargs:
            kwargs["data"] = json.dumps(kwargs["data"], cls=KRestJSONEncoder)
            logger.debug("Request data: %s", kwargs["data"])
        if "raw" in kwargs:
            raw = kwargs["raw"]
            del kwargs["raw"]
        else:
            raw = False
        headers = {'content-type': 'application/json'}
        if hasattr(self.ReqCfg, "headers"):
            headers.update(self.ReqCfg.headers)
        kwargs.update(self.req_cfg.__dict__)
        rv = self.session.request(method, endpoint, auth=self.auth, verify=self.ssl_validate, headers=headers, **kwargs)
        rv.raise_for_status()
        if rv.content and not raw:
            rv = rv.json()
        logger.debug("Returned value is: %s", rv)
        return rv

    def _resource_url(self, resource_type):
        endpoint = self.api_prefix + self.resources[resource_type]
        return urlparse.urljoin(self.base_url, endpoint)

    def _obj_ref(self, resource_type, id):
        return "%s/%s" % (self.resources[resource_type], id)

    def _obj_url(self, resource_type, id):
        return "%s/%s" % (self._resource_url(resource_type), id)

    def get(self, resource_type, id):
        rv = self._request("GET", self._obj_url(resource_type, id))
        ro = RestObject(self, resource_type, **rv)
        return ro

    def post(self, ro):
        rv = self._request("POST", self._resource_url(ro._resource_type), data=ro._current)
        ro._update(**rv)
        return ro

    def patch(self, ro):
        if not ro._changed:
            return
        rv = self._request("PATCH", ro._obj_url, data=ro._changed)
        ro._update(**rv)
        return ro

    def delete(self, ro):
        self._request("DELETE", ro._obj_url)

    def new(self, resource_type, **attrs):
        if resource_type not in self.resources:
            raise ValueError("Unknown resource_type: %s" % resource_type)
        return RestObject(self, resource_type, **attrs)

    def discover(self):
        self.resources = dict()
        self.resource_endpoints = dict()
        data = self._request("GET", urlparse.urljoin(self.base_url, self.api_prefix))
        for k, v in data["resources"].items():
            self.resources[k] = v["url"]
            self.resource_endpoints[v["url"]] = k

    def _serialize_query_objects(self, query):
        for k, v in query.items():
            if isinstance(v, RestObject):
                del query[k]
                k = k + ".ref"
                query[k] = v._obj_ref

    def search(self, resource_type, **query):
        self._serialize_query_objects(query)
        url = self._resource_url(resource_type)
        url += "?%s" % urllib.urlencode(query)
        data = self._request("GET", url)
        new_hits = list()
        for hit in data["hits"]:
            new_hits.append(RestObject(self, resource_type, **hit))
        data["hits"] = new_hits
        rs = ResultSet(self, resource_type, data, query)
        return rs

    def dump_all(self, fp, pretty=False, read_chunk=8192):
        """Dumps all objects in raw JSON to a provided file descriptor"""
        url = urlparse.urljoin(self.base_url, self.full_endpoint)
        if pretty:
            sep = "&" if "?" in url else "?"
            url = "%s%s__pretty" % (url, sep)
        r = self._request("GET", url, raw=True, stream=True)
        for chunk in r.iter_content(read_chunk):
            fp.write(chunk)


class RestObjectProxy(object):
    def __init__(self, ep, ref):
        self._ep = ep
        (self._resource_endpoint, _, self.id) = ref["ref"].rpartition("/")
        self.id = int(self.id)
        self._resource_type = self._ep.resource_endpoints[self._resource_endpoint]

    def __call__(self):
        ro = self._ep.get(self._resource_type, self.id)
        return ro

    def __eq__(self, other, shallow=None):
        # "shallow" parameter is supported for compatability -
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


class RestObject(object):
    def __init__(self, ep, resource_type, **kwargs):
        self._ep = ep
        self._resource_type = resource_type
        self._update(**kwargs)

    def save(self):
        if hasattr(self, "id"):
            # construct things that changed and run patch
            return self._ep.patch(self)
        else:
            return self._ep.post(self)

    def delete(self):
        return self._ep.delete(self)

    def refresh(self):
        if not hasattr(self, "id"):
            return
        new_obj = self._ep.get(self._resource_type, self.id)
        self._update(**new_obj._current)

    def __setattr__(self, attr, val):
        if not attr.startswith("_"):
            self._changed[attr] = self._current[attr] = val
            return
        super(RestObject, self).__setattr__(attr, val)

    def __getattr__(self, attr):
        val = self._current[attr]
        if isinstance(val, RestObjectProxy):
            val = val()
            self._current[attr] = val
        return val

    def _update(self, **kwargs):
        self._current = dict()
        for k, v in kwargs.items():
            if isinstance(v, dict) and "ref" in v:
                self._current[k] = RestObjectProxy(self._ep, v)
            else:
                self._current[k] = v
        self._changed = dict()

    def __str__(self):
        return "<%s('%s') %s>" % (self.__class__.__name__, self._resource_type, (self._current))

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
    def __init__(self, ep, resource_type, data, query):
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
            if not self.autofetch:
                raise StopIteration
            self.next_chunk()
            if not self.hits:
                raise StopIteration
        rv = self.hits[self._current_hit_index]
        self._current_hit_index += 1
        return rv

    def next_chunk(self):
        if "__offset" in self._query:
            self._query["__offset"] += self.limit
        else:
            self._query["__offset"] = self.limit
        rs = self._ep.search(self._resource_type, **self._query)
        af = self.autofetch
        self.__dict__.update(rs.__dict__)
        self.autofetch = af
