from __future__ import absolute_import

__version__ = "1.1.3"

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


class KRestJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (RestObject, RestObjectProxy)):
            return o._ref
        return super(KRestJSONEncoder, self).default(o)


logger = logging.getLogger("krest")


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

    def __init__(self, k2_addr, username, password, ssl_validate=True,
                 autodiscover=True,
                 lazy_load_references=True,
                 parse_references=True):

        self.full_endpoint = "%s/%s" % (self.api_prefix, "__full")

        self.lazy_load_references = lazy_load_references
        self.parse_references = parse_references

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
            retry_too_fast = False
            while retry:
                retry = False
                try:
                    return func(self, *args, **kwargs)
                except ConnectionError, err:
                    logger.error("Connection Error: %s", str(err))
                    if self.retry_cfg.on_connect_errors:
                        retry = True
                except HTTPError, err:
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
                except Exception, err:
                    logger.error("Error: %s", str(err))
                    retry = False
                if retry and time.time() - start_time < self.retry_cfg.not_reachable_timeout:
                    logger.error("Sleeping for %s seconds", self.retry_cfg.not_reachable_pause)
                    time.sleep(self.retry_cfg.not_reachable_pause)
                    logger.error("Retrying")
                elif retry_too_fast:
                    time.sleep(self.retry_cfg.toofast_pause)
                    retry = True
                else:
                    if isinstance(err, HTTPError):
                        raise self._rebuild_err(err)
                    else:
                        raise err
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
            req_args["data"] = json.dumps(req_args["data"], cls=KRestJSONEncoder)
            logger.info("Request data: %s" % req_args["data"])

    def _prepare_request_headers(self, req_args):
        headers = {'content-type': 'application/json'}
        if hasattr(self.req_cfg, "headers"):
            headers.update(self.req_cfg.headers)
        if "headers" in req_args:
            headers.update(req_args["headers"])

        req_args.update(self.req_cfg.__dict__)
        # Taking out "headers" field from req_args - we pass it explicitly
        if "headers" in req_args:
            del req_args["headers"]

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

    #noinspection PyArgumentList
    @exception_wrapper
    def _request(self, method, endpoint, options={}, **kwargs):
        logger.info("Method: %s - Sending: %s" % (str(method), str(endpoint)))

        self._prepare_request_timeout(kwargs, options)
        self._prepare_request_data(kwargs)
        headers = self._prepare_request_headers(kwargs)

        raw = options.get("raw", False)
        kwargs["stream"] = options.get("stream", True) if raw else options.get("stream", False)

        rv = self.session.request(method, endpoint, auth=self.auth, verify=self.ssl_validate, headers=headers, **kwargs)
        rv.raise_for_status()

        # WARNING: Evaluating value of rv.content will negate the effect of stream=True
        if not raw and rv.content:
            rv = rv.json()
        logger.info("Returned value is: %s", rv)
        return rv

    def _resource_url(self, resource_type):
        endpoint = self.api_prefix + self.resources[resource_type]
        return urlparse.urljoin(self.base_url, endpoint)

    def _obj_ref(self, resource_type, id):
        return "%s/%s" % (self.resources[resource_type], id)

    def _obj_url(self, resource_type, id):
        return "%s/%s" % (self._resource_url(resource_type), id)

    def get(self, resource_type, id, options={}):
        rv = self._request("GET", self._obj_url(resource_type, id), options=options)
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

    def delete(self, ro, options={}):
        self._request("DELETE", ro._obj_url, options=options)

    def new(self, resource_type, **attrs):
        if resource_type not in self.resources:
            raise ValueError("Unknown resource_type: %s" % resource_type)
        return RestObject.new(self, resource_type, **attrs)

    def discover(self, options={}):
        self.resources = dict()
        self.resource_endpoints = dict()
        data = self._request("GET", urlparse.urljoin(self.base_url, self.api_prefix), options=options)
        for k, v in data["resources"].items():
            self.resources[k] = v["url"]
            self.resource_endpoints[v["url"]] = k

    def _serialize_query_objects(self, query):
        for k, v in query.items():
            if isinstance(v, RestObjectBase):
                del query[k]
                k = k + ".ref"
                query[k] = v._obj_ref
                continue

            if isinstance(v, ResultSet):
                v = v.hits
            if isinstance(v, (list, tuple)):
                if k.endswith("__m_eq") or k.endswith("__in"):
                    continue
                del query[k]
                print len(v)
                k += ".ref__m_eq" if isinstance(v[0], RestObjectBase) else "__m_eq"
                query[k] = ",".join(_v._obj_ref if isinstance(_v, RestObjectBase) else _v for _v in v)
                continue

    def search(self, resource_type, options={}, **query):
        self._serialize_query_objects(query)
        url = self._resource_url(resource_type)
        url += "?%s" % urllib.urlencode(query)

        data = self._request("GET", url, options=options)
        if options.get("raw", False):
            if options.get("fp", None):
                return self.stream_response_to_file(data, options["fp"])
            return data

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

    def __str__(self):
        return "<%s('%s') %s>" % (self.__class__.__name__, self._resource_type, self._ref)


class RestObject(RestObjectBase):
    def __init__(self, ep, resource_type, **kwargs):
        self._ep = ep
        self._resource_type = resource_type
        self._update(**kwargs)

    @classmethod
    def new(cls, ep, resource_type, **kwargs):
        obj = cls(ep, resource_type, **kwargs)
        obj._changed = obj._current
        return obj

    def save(self, options={}):
        if hasattr(self, "id"):
            # construct things that changed and run patch
            return self._ep.patch(self, options=options)
        else:
            return self._ep.post(self, options=options)

    def delete(self, options={}):
        return self._ep.delete(self, options=options)

    def refresh(self, options={}):
        if not hasattr(self, "id"):
            return
        new_obj = self._ep.get(self._resource_type, self.id, options=options)
        self._update(**new_obj._current)

    def __setattr__(self, attr, val):
        if not attr.startswith("_"):
            self._changed[attr] = self._current[attr] = val
            return
        super(RestObject, self).__setattr__(attr, val)

    def __getattr__(self, attr):
        val = self._current[attr]
        if self._ep.lazy_load_references and isinstance(val, RestObjectProxy):
            val = val()
            self._current[attr] = val
        return val

    def _update(self, **kwargs):
        self._current = dict()
        for k, v in kwargs.items():
            if self._ep.parse_references and isinstance(v, dict) and "ref" in v:
                self._current[k] = RestObjectProxy(self._ep, v)
            else:
                self._current[k] = v
        self._changed = dict()

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

    def __nonzero__(self):
        return bool(self.hits)
