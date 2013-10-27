from __future__ import absolute_import

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
# import logging
#logging.addHandler(km_log_handler)
#logging.getLogger("krest").setLevel(logging.DEBUG)
#logging.getLogger("request").setLevel(logging.DEBUG)


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

    def __init__(self, k2_addr, username, password, ssl_validate=True):
        self.ssl_validate = ssl_validate
        self.base_url = "https://%s" % k2_addr
        self.auth = (username, password)
        self.session = requests.Session()

        self.req_cfg = self.ReqCfg()
        self.retry_cfg = self.RetryCfg()

        self.discover()

    def exception_wrapper(func):
        @wraps(func)
        def wrapped(self, *args, **kwargs):
            start_time = time.time()
            retry = True
            while retry and time.time() - start_time < self.retry_cfg.not_reachable_timeout:
                try:
                    return func(self, *args, **kwargs)
                except ConnectionError, err:
                    if self.retry_cfg.connect_errors:
                        retry = True
                except HTTPError, err:
                    if self.retry_cfg.http_errors:
                        retry = True
                except Exception, err:
                    retry = False
                if retry:
                    time.sleep(self.retry_cfg.not_reachable_pause)
                else:
                    raise err
        return wrapped

    #noinspection PyArgumentList
    @exception_wrapper
    def _request(self, method, endpoint, **kwargs):
        headers = {'content-type': 'application/json'}
        if "data" in kwargs:
            kwargs["data"] = json.dumps(kwargs["data"], cls=KRestJSONEncoder)
        kwargs.update(self.req_cfg.__dict__)
        rv = method(endpoint, auth=self.auth, verify=self.ssl_validate, headers=headers, **kwargs)
        rv.raise_for_status()
        if rv.content:
            rv = rv.json()
        return rv

    def _get(self, endpoint):
        return self._request(self.session.get, endpoint)

    def _post(self, endpoint, **kwargs):
        return self._request(self.session.post, endpoint, **kwargs)

    def _patch(self, endpoint, **kwargs):
        return self._request(self.session.patch, endpoint, **kwargs)

    def _delete(self, endpoint):
        return self._request(self.session.delete, endpoint)

    def _resource_url(self, resource_type):
        endpoint = self.api_prefix + self.resources[resource_type]
        return urlparse.urljoin(self.base_url, endpoint)

    def _obj_url(self, resource_type, id):
        return "%s/%s" % (self._resource_url(resource_type), id)

    def get(self, resource_type, id):
        rv = self._get(self._obj_url(resource_type, id))
        ro = RestObject(self, resource_type, **rv)
        return ro

    def post(self, ro):
        rv = self._post(self._resource_url(ro._resource_type), data=ro._current)
        ro._update(**rv)
        return ro

    def patch(self, ro):
        if not ro._changed:
            return
        rv = self._patch(ro._obj_url, data=ro._changed)
        ro._update(**rv)
        return ro

    def delete(self, ro):
        self._delete(ro._obj_url)

    def new(self, resource_type, **attrs):
        if resource_type not in self.resources:
            raise ValueError("Unknown resource_type: %s" % resource_type)
        return RestObject(self, resource_type, **attrs)

    def discover(self):
        self.resources = dict()
        self.resource_endpoints = dict()
        data = self._get(urlparse.urljoin(self.base_url, self.api_prefix))
        for k, v in data["resources"].items():
            self.resources[k] = v["url"]
            self.resource_endpoints[v["url"]] = k

    def search(self, resource_type, **query):
        url = self._resource_url(resource_type)
        url += "?%s" % urllib.urlencode(query)
        data = self._get(url)
        new_hits = list()
        for hit in data["hits"]:
            new_hits.append(RestObject(self, resource_type, **hit))
        data["hits"] = new_hits
        rs = ResultSet(data["hits"], data["total"], data["limit"], data["offset"], resource_type, query)
        return rs


class RestObjectProxy(object):
    def __init__(self, attr_name, ep, ref):
        self.ep = ep
        (self.resource_endpoint, _, self.id) = ref["ref"].rpartition("/")
        self.resource_type = self.ep.resource_endpoints[self.resource_endpoint]
        self.attr_name = attr_name

    def __call__(self):
        ro = self.ep.get(self.resource_type, self.id)
        return ro


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
                self._current[k] = RestObjectProxy(k, self._ep, v)
            else:
                self._current[k] = v
        self._changed = dict()

    def __str__(self):
        return "<%s('%s') %s>" % (self.__class__.__name__, self._resource_type, (self._current))

    def __repr__(self):
        return self.__str__()

    @property
    def _obj_url(self):
        return self._ep._obj_url(self._resource_type, self.id)

    @property
    def _ref(self):
        return {"ref": "/%s/%s" % (self._resource_type, self.id)}


class ResultSet(object):
    """
    Simple object for working with results set.
    We can enhace it later to support result chunks iteration, etc
    """
    def __init__(self, hits, total, limit, offset, resource_type, query):
        self.hits = hits
        self.total = total
        self.limit = limit
        self.offset = offset
        self._resource_type = resource_type
        self._query = query

    def delete_all(self):
        for hit in self.hits:
            hit.delete()