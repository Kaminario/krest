import unittest
import os
from functools import wraps
import time
import logging

from requests.exceptions import ConnectionError, HTTPError
import krest

KREST_HOST = os.environ.get("KREST_HOST", "localhost")
KREST_USER = os.environ.get("KREST_USER", "root")
KREST_PASSWORD = os.environ.get("KREST_PASSWORD", "password")

not_reachable_timeout = 10
not_reachable_pause = 1


class KrestTest(unittest.TestCase):
    def setUp(self):
        krest.EndPoint.RetryCfg.not_reachable_timeout = not_reachable_timeout
        krest.EndPoint.RetryCfg.not_reachable_pause = not_reachable_pause
        self.ep = krest.EndPoint(KREST_HOST, KREST_USER, KREST_PASSWORD, ssl_validate=False)

    def should_complete_in(seconds):
        def inner(func):
            @wraps(func)
            def wrapper(self):
                start = time.time()
                func(self)
                finish = time.time()
                took = finish - start
                self.assertTrue(took < seconds,
                                "Test failed to complete within %s seconds. Took %s" % (seconds, took))
            return wrapper
        return inner

    def should_not_complete_before(seconds):
        def inner(func):
            @wraps(func)
            def wrapper(self):
                start = time.time()
                func(self)
                finish = time.time()
                took = finish - start
                self.assertTrue(took > seconds,
                                "Test finished before %s seconds. Took %s" % (seconds, took))
            return wrapper
        return inner

    @should_complete_in(1)
    def test_junk_request(self):
        self.assertRaises(KeyError, self.ep.search, "no_such_thing")

    @should_complete_in(30)
    def test_bad_request(self):
        v = self.ep.new("volumes", name="CTRL")
        self.assertRaises(HTTPError, v.save)

    @should_complete_in(2)
    def test_not_found(self):
        self.assertRaises(HTTPError, self.ep.get, "events", 0)

    @should_complete_in(not_reachable_timeout*1.15)
    @should_not_complete_before(not_reachable_timeout)
    def test_not_found_retries(self):
        self.ep.retry_cfg.on_4xx_errors = True
        self.assertRaises(HTTPError, self.ep.get, "events", 0)

    @should_complete_in(not_reachable_timeout*1.15)
    @should_not_complete_before(not_reachable_timeout)
    def test_connect_retries(self):
        self.assertRaises(ConnectionError, krest.EndPoint,
                          "127.0.0.111", KREST_USER, KREST_PASSWORD, ssl_validate=False)

    @should_complete_in(1)
    def test_connect(self):
        class MyEndpoint(krest.EndPoint):
            class RetryCfg(krest.EndPoint.RetryCfg):
                on_connect_errors = False
        self.assertRaises(ConnectionError, MyEndpoint,
                          "127.0.0.111", KREST_USER, KREST_PASSWORD, ssl_validate=False)

    @should_complete_in(1)
    def test_5xx_errors(self):
        self.ep.retry_cfg.on_5xx_errors = False
        self.assertRaises(HTTPError, self.ep.search, "stats/system")

    @should_complete_in(not_reachable_timeout*1.15)
    @should_not_complete_before(not_reachable_timeout)
    def test_5xx_errors_retries(self):
        self.assertRaises(HTTPError, self.ep.search, "stats/system")

    @should_complete_in(5)
    def test_bad_auth(self):
        self.assertRaises(HTTPError, krest.EndPoint,
                          KREST_HOST, "buba", "mara", ssl_validate=False)

    @should_complete_in(not_reachable_timeout*1.15)
    @should_not_complete_before(not_reachable_timeout)
    def test_bad_auth_retries(self):
        class MyEndpoint(krest.EndPoint):
            class RetryCfg(krest.EndPoint.RetryCfg):
                on_auth_required = True
        self.assertRaises(HTTPError, MyEndpoint,
                          KREST_HOST, "buba", "mara", ssl_validate=False)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    unittest.main()
