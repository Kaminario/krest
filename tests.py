#
# (c) 2015 Kaminario Technologies, Ltd.
#
# This software is licensed solely under the terms of the Apache 2.0 license,
# the text of which is available at http://www.apache.org/licenses/LICENSE-2.0.
# All disclaimers and limitations of liability set forth in the Apache 2.0 license apply.
#

import unittest
import os
from functools import wraps, partial
import time
import logging
import threading
import random
from distutils.version import StrictVersion

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
        self.system_state = self.ep.get("system/state", 1)
        self.to_clean = list()

    def tearDown(self):
        for item in self.to_clean[::-1]:
            try:
                item.delete()
            except:
                pass

    def should_complete_in(seconds):
        def inner(func):
            @wraps(func)
            def wrapper(self, *args, **kwargs):
                start = time.time()
                func(self, *args, **kwargs)
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

    def min_api_version(version):
        def inner(func):
            @wraps(func)
            def wrapper(self):
                api_version = getattr(self.system_state, "rest_api_version", None)
                if not api_version:
                    self.skipTest("Skipping test. This is an older k2 that does not specify API version")
                if StrictVersion(api_version) < StrictVersion(api_version):
                    self.skipTest("Skipping test. Requires at least version %s of the API" % version)
                func(self)
            return wrapper
        return inner

    @should_complete_in(1)
    def test_junk_request(self):
        self.assertRaises(KeyError, self.ep.search, "no_such_thing")

    @should_complete_in(30)
    def test_bad_request(self):
        self.create_volume_objects()
        v = self.ep.search("volumes").hits[0]
        newv = self.ep.new("volumes", name=v.name)
        self.assertRaises(HTTPError, newv.save)

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
        if self.system_state.state == "ONLINE":
            self.skipTest("Can not test 5xx errors while system is ONLINE")
        self.ep.retry_cfg.on_5xx_errors = False
        self.assertRaises(HTTPError, self.ep.search, "stats/system")

    @should_complete_in(not_reachable_timeout*1.15)
    @should_not_complete_before(not_reachable_timeout)
    def test_5xx_errors_retries(self):
        if self.system_state.state == "ONLINE":
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
        self.to_clean.append(vg)
        vol = self.ep.new("volumes",
                          name="%s_unittest_v%s" % (vg.name, index),
                          size=1*2**30, volume_group=vg).save()
        self.to_clean.append(vol)
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

    def loader(self, *args, **kwargs):
        try:
            for i in range(100):
                self.ep.get("system/state", 1)
        except:
            return

    def verify_not_root(self):
        if self.ep.get("system/state", 1).current_user_role == "root":
            self.skipTest("There is no request rate enforcment on root-grade users")

    def test_toofast(self):
        """Test that speed rate is enforced by server"""
        self.verify_not_root()
        loader = threading.Thread(target=self.loader)
        loader.start()
        success = False
        try:
            for i in range(100):
                if success:
                    break
                self.ep.get("system/state", 1)
        except krest.HTTPError as err:
            if err.response.status_code == 429:
                success = True
            else:
                raise
        loader.join()
        time.sleep(1)  # To free some bandwith for those after us to run
        self.assertTrue(success, "Request rate limiting seems not to function")

    def test_toofast_retries(self):
        """Test that too-fast retries are working"""
        self.verify_not_root()
        self.ep.retry_cfg.on_toofast_error = True
        loader = threading.Thread(target=self.loader)
        loader.start()
        for i in range(100):
            self.ep.get("system/state", 1)
        loader.join()
        time.sleep(1)  # To free some bandwith for those after us to run

    def test_in_place_update(self):
        """Check we can use ep.new(...) to update object"""
        self.create_volume_objects(index=1)
        vg_id = self.ep.search("volume_groups", name="unittest_vg1").hits[0].id
        tst_desc = "tst_desc"
        self.ep.new("volume_groups", id=vg_id, description=tst_desc).save()
        vg = self.ep.get("volume_groups", vg_id)
        self.assertEqual(vg.description, tst_desc, msg="Failed to update VG description")

    def test_custom_headers(self):
        """Test that headers override is working"""
        self.create_volume_objects(index=1)
        self.ep.req_cfg.headers = {"Foo": "Bar"}
        try:
            self.create_volume_objects(index=1)
        except krest.HTTPError as err:
            self.assertIn("Foo", err.response.request.headers)
            self.assertEqual("Bar", err.response.request.headers["Foo"])
        else:
            self.fail("Creaing objects with similar names did not raise exception")

    def test_lazy_load(self):
        """Test that referneces lazy loading is working"""
        self.create_volume_objects()
        vol = self.ep.search("volumes", id__gt=1).hits[0]
        vol.volume_group.name

    def test_no_lazy_load(self):
        """Test that DISABLING referneces lazy loading is working"""
        self.create_volume_objects()
        self.ep.lazy_load_references = False
        vol = self.ep.search("volumes", id__gt=1).hits[0]
        vol.volume_group
        self.assertIsInstance(vol.volume_group, krest.RestObjectProxy)

    def test_no_ref_parsing(self):
        """Test that DISABLING refernece parsing is working"""
        self.create_volume_objects()
        self.ep.parse_references = False
        vol = self.ep.search("volumes", id__gt=1).hits[0]
        vol.volume_group
        self.assertIsInstance(vol.volume_group, dict)

    def _test_request_timeout(self, options={}):
        Timeout = krest.requests.exceptions.Timeout

        getter = partial(self.ep.get, "system/state", 1, options=options)
        self.assertRaises(Timeout, getter)

        searcher = partial(self.ep.search, "system/state", options=options)
        self.assertRaises(Timeout, searcher)

        sysstate = self.ep.new("system/state", foo="bar")
        poster = partial(sysstate.save, options=options)
        self.assertRaises(Timeout, poster)

        sysstate = self.ep.new("system/state", id=1, foo="bar")
        patcher = partial(sysstate.save, options=options)
        self.assertRaises(Timeout, patcher)

        deleter = partial(sysstate.delete, options=options)
        self.assertRaises(Timeout, deleter)

        refresher = partial(sysstate.refresh, options=options)
        self.assertRaises(Timeout, refresher)

    def test_request_timeout_through_options(self):
        """Test that timeouts are working through options dictionary"""
        options = {"timeout": 0.000001}
        self._test_request_timeout(options=options)

    def test_request_timeout_through_req_cfg(self):
        """Test that timeouts are working through options dictionary"""
        self.ep.req_cfg.timeout = 0.000001
        self._test_request_timeout()

    def test_patch(self):
        """Test that object updating works"""
        self.create_volume_objects(index=1)
        vg = self.ep.search("volume_groups", name="unittest_vg1").hits[0]
        tst_desc = "tst_desc"
        vg.description = tst_desc
        vg.save()
        vg = self.ep.get("volume_groups", vg.id)
        self.assertEqual(vg.description, tst_desc, msg="Failed to update VG description")

    def _test_list(self, rest_objects=True):
        self.create_volume_objects(index=1)
        self.create_volume_objects(index=2)

        vols_single = []

        if rest_objects:
            vgs = self.ep.search("volume_groups", __limit=2)
            for vg in vgs:
                vols_single.extend(self.ep.search("volumes", volume_group=vg).hits)
            vols_multi = self.ep.search("volumes", volume_group=vgs).hits
        else:
            vols = self.ep.search("volumes", __limit=2)
            for v in vols:
                vols_single.extend(self.ep.search("volumes", name=v.name).hits)
            vols_multi = self.ep.search("volumes", name=[v.name for v in vols]).hits

        self.assertEqual(len(vols_multi), len(vols_single),
                         msg="Single and multi queries returned different amount of results")
        for v in vols_multi:
            self.assertIn(v, vols_single, msg="Multi query returned result that was not in single query")

    def test_list_rest_objects(self):
        """
        Test that list search argument automatically turns on __m_eq serializaion.
        For RestObjects.
        """
        self._test_list(rest_objects=True)

    def test_list_simple(self):
        """
        Test that list search argument automatically turns on __m_eq serializaion
        For simple types.
        """
        self._test_list(rest_objects=False)

    def test_validate_endpoints(self):
        """Test that endpoint validation works properly"""
        self.assertRaises(ValueError, self.ep.new, "asdfasdf", name=1)

        ep = krest.EndPoint(KREST_HOST, KREST_USER, KREST_PASSWORD, ssl_validate=False,
                            autodiscover=False,
                            validate_endpoints=False)
        try:
            ep.new("blah", name=1)
        except ValueError:
            self.fail("Failed to create object on non-existing endpoint, although validate_endpoints=False")

        hg = ep.new("host_groups", name="unittest_hg1").save()
        self.to_clean.append(hg)

    @min_api_version("2.1.0")
    def test_sequences(self):

        sid1 = "krest%s" % random.random()
        sid2 = "krest%s" % random.random()
        sid3 = "krest%s" % random.random()
        sequences = {sid1: 1, sid2: 1, sid3: 1}

        hg = self.ep.new("host_groups", name="unittest_hg1")
        hg.save(options={"sequence": sequences})
        self.to_clean.append(hg)

        hg = self.ep.new("host_groups", name="unittest_hg2")

        try:
            sequences = {sid1: 1, sid2: 1, sid3: 1}
            hg.save(options={"sequence": sequences})
        except krest.HTTPError as err:
            self.assertEqual(err.response.status_code, 409)
        try:
            sequences = {sid1: 1, sid2: 1, sid3: 2}
            hg.save(options={"sequence": sequences})
        except krest.HTTPError as err:
            self.assertEqual(err.response.status_code, 409)
        try:
            sequences = {sid1: 1, sid2: 2, sid3: 2}
            hg.save(options={"sequence": sequences})
        except krest.HTTPError as err:
            self.assertEqual(err.response.status_code, 409)
        sequences = {sid1: 2, sid2: 2, sid3: 2}
        hg.save(options={"sequence": sequences})
        self.to_clean.append(hg)

    def test_get(self):
        """Test that ep.get is working"""
        v = self.ep.get("volumes", 1)
        self.assertEqual(v.id, 1, msg="Got bogus response instead of volume with id=1")

    @min_api_version("2.1.0")
    def test_fields_get(self):
        """Test.that __fields filtering is working with .get"""
        v = self.ep.get("volumes", 1, __fields=["id", "name"])
        self.assertEqual(set(v._current.keys()), set(["id", "name"]))

    @min_api_version("2.1.0")
    def test_fields_search(self):
        """Test.that __fields filtering is working with .search"""
        v = self.ep.search("volumes", id=1, __fields=["id", "name"]).hits[0]
        self.assertEqual(set(v._current.keys()), set(["id", "name"]))

    @min_api_version("2.1.0")
    def test_bulk_post(self):
        self.create_volume_objects(index=1)
        self.create_volume_objects(index=2)
        retpol = self.ep.search("retention_policies").hits[0]

        req = self.ep.new("snapshots", bulk=True)
        self.assertIsInstance(req, krest.BulkRequest)
        for i, vg in enumerate(self.ep.search("volume_groups", name__contains="unittest")):
            s = self.ep.new("snapshots", short_name="unittest_snap%s" % i, source=vg, retention_policy=retpol)
            req.add(s)

        snapshots = req.post()
        self.to_clean.extend(snapshots)

        snap_names = [s.short_name for s in req]
        self.assertEqual(len(snapshots), len(req))
        for s in snapshots:
            self.assertIn(s.short_name, snap_names)

        req = self.ep.new("snapshots", bulk=True)
        req.add(snapshots)
        req.delete()
        snapshots = self.ep.search("snapshots", name__contains_some="unittest_snap")
        self.assertFalse(snapshots.hits, msg="Bulk delete did not work")

    def test_stats(self):
        """Test that performance fetching works"""
        self.ep.search("stats/system")
        self.ep.search("stats/volumes")

    @min_api_version("2.1.0")
    def test_stats_fields(self):
        """Test that performance fields filtering works"""
        for endpoint in ["stats/system", "stats/volumes"]:
            hits = self.ep.search(endpoint, __fields=["iops_avg", "throughput_avg"]).hits
            if not hits:
                self.skipTest("No IO in the system")
            self.assertEqual(set(hits[0]._current.keys()), set(["iops_avg", "throughput_avg"]))

    def test_stats_speed(self):
        """Test that system performance fetching works fast"""

        if self.system_state.state != "ONLINE":
            self.skipTest("Can not test stats speed while system is ONLINE")

        mapnum = self.ep.search("mappings", __limit=0).total
        if mapnum < 50:
            self.skipTest("Stats speed testing requies at least 50 mapped volumes")

        should_complete_in = self.__class__.__dict__["should_complete_in"]

        def search(*args, **kwargs):
            self.ep.search("stats/system", __datapoints=12)
        should_complete_in(1)(search)(self)

        def search(*args, **kwargs):
            self.ep.search("stats/system", __datapoints=12, __resolution="5m")
        should_complete_in(1)(search)(self)

        def search(*args, **kwargs):
            self.ep.search("stats/system", __datapoints=12, __resolution="1h")
        should_complete_in(1)(search)(self)

        # Current stats for 100 volumes should not take more then a second
        # If there are less then 100 mapping, just use second
        t = max(1, float(mapnum)/100)

        def search(*args, **kwargs):
            self.ep.search("stats/volumes")
        should_complete_in(t)(search)(self)

        for i in [10, 100, 1000]:
            def search(*args, **kwargs):
                self.ep.search("stats/volumes", __datapoints=i)
            should_complete_in(t+float(i)/8)(search)(self)

    def test_get_raw(self):
        """Test that ._get_raw is working"""
        self.create_volume_objects()
        v = self.ep.search("volumes", name__contains_some="unittest").hits[0]
        self.assertIsInstance(v._get_raw("volume_group"), krest.RestObjectProxy)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    unittest.main()
