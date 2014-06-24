import unittest
import os
from functools import wraps
import time
import logging
from collections import deque

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
        self.system_state = self.ep.get("system/state", 1).state
        self.to_clean = deque()

    def tearDown(self):
        for item in self.to_clean:
            try:
                item.delete()
            except Exception:
                pass

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
        if self.system_state == "ONLINE":
            self.skipTest("Can not test 5xx errors while system is ONLINE")
        self.ep.retry_cfg.on_5xx_errors = False
        self.assertRaises(HTTPError, self.ep.search, "stats/system")

    @should_complete_in(not_reachable_timeout*1.15)
    @should_not_complete_before(not_reachable_timeout)
    def test_5xx_errors_retries(self):
        if self.system_state == "ONLINE":
            self.skipTest("Can not test 5xx errors while system is ONLINE")
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

    def create_volume_objects(self, index="1"):
        vg = self.ep.new("volume_groups",
                         name="unittest_vg%s" % index,
                         quota=0).save()
        self.to_clean.appendleft(vg)
        vol = self.ep.new("volumes",
                          name="%s_unittest_v%s" % (vg.name, index),
                          size=1*2**30, volume_group=vg).save()
        self.to_clean.appendleft(vol)
        return vg, vol

    def verify_vol_search(self, o_vols, n_vols):
        n_ids = [v.id for v in n_vols]
        o_ids = [v.id for v in o_vols]
        for o_id in o_ids:
            self.assertTrue(o_id in n_ids, msg="volume with %s was not found in K2" % o_id)

    def test_query_serialize(self):
        """Test we can do ep.search(.., volume=<RestObject>"""
        vg, vol = self.create_volume_objects()
        svol = self.ep.search("volumes", volume_group=vg)
        self.assertTrue(svol, msg="Returned empty search result")
        svol = svol.hits[0]
        self.assertEqual(vol.id, svol.id, msg="Search yielded different volume")

    def check_query_serialize_multiple(self, method):
        vg1, vol1 = self.create_volume_objects(index=1)
        vg2, vol2 = self.create_volume_objects(index=2)
        if method == "rs":
            vgs = self.ep.search("volume_groups", name=[vg1.name, vg2.name])
            self.assertEqual(len(vgs.hits), 2, msg="Too many/little volume groups returned")
            vols = self.ep.search("volumes", volume_group=vgs)
        else:
            vols = self.ep.search("volumes", volume_group=[vg1, vg2])
        self.assertEqual(len(vols.hits), 2, msg="Too many/little volume returned")
        self.verify_vol_search((vol1, vol2), vols)

    def test_query_serialize_multiple_rs(self):
        """Test we can do ep.search(.., volume=<ResultSet>"""
        self.check_query_serialize_multiple("rs")

    def test_query_serialize_multiple_list(self):
        """Test we can do ep.search(.., volume=<list>"""
        self.check_query_serialize_multiple("list")

    def test_query_serialize_multiple_skip(self):
        """Test that no serializaion occurs of we do it ourself beforehand"""
        vg1, vol1 = self.create_volume_objects(index=1)
        vg2, vol2 = self.create_volume_objects(index=2)
        vgs = self.ep.search("volume_groups", name__m_eq=",".join([vg1.name, vg2.name]))

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    unittest.main()
