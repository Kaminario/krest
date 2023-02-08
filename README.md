![PyPi version](https://img.shields.io/pypi/v/krest.svg)

# krest

The Silk REST (krest) is a client library that provides ORM like interface for working with Silk SDP
REST API.

Krest is written in Python and is aimed to provide rapid enablement of managing
and monitoring SDPs all-flash arrays using Python.

This readme file complements the Silk SDP REST API guide document. You can request 
this document from the Silk support team.

# Installation
```
pip install krest
```

# Usage

## login
Below are the examples of using krest. Again, we'll mostly explain how the Python interface
maps to a URL spec which is outlined in SDP REST API guide.

First you need to obtain an endpoint (connection) to your SDP:
```
import krest
basic_auth = krest.KrestBasicAuth("username", "password")
ep = krest.EndPoint("SDP IP address", auth=basic_auth, ssl_validate=False)
```

In case you are using an "app token" from Flex you should connect to your SDP via Flex:
```
import krest
bearer_auth = krest.KrestBearerAuth("your token")
ep = krest.EndPoint('Flex IP address', sdp_id="SDP ID", auth=bearer_auth, ssl_validate=False)
```

If you configured your SDP with real SSL certificates, set `ssl_validate=True` in the above call.


## Creating and changing objects

Once you've obtained an endpoint, you can use it to CREATE/READ/UPDATE/DELETE objects.
```
# create host-group
hg = ep.new("host_groups")
hg.name = "hg1"
hg.save()
```

Parameters can also be passed inline:
```
# save() also returns the updated object
host = ep.new("hosts", name="h1", type="Linux", host_group=hg).save()
```
Note how we can use our `hg` object as host-group reference in newly created volume above.

Changing is simple - just change attributes and hit `.save()`
```
host.type = "Windows"
host.name = "h2"
host.save()
```

## Searching stuff

If you know a specific object id, you can `.get()` it:
```
vol = ep.get("volumes", 1)
```

Otherwise use `.search()` to retrieve multiple objects that match search query.
In the simplest form:
```
rv = ep.search("hosts", name="h2") 
```
The returned object is a `ResultSet` object that has a `.hits` array containing `RestObject`s.
The total number of matched objects is recorded in the `ResultSet.total` attribute.

`.search()` method recieves `resource_type`, `options` and query keyword arguments.
Each query argument is treated as a field name and its value and a requested field value.
i.e. in the above example, we search for hosts having `name="h2"`. 

You can add search modifiers to field names:
```
rv = ep.search("events", level="INFO", message__contains="h1", name__contains="HOST")
```
For the full list of search modifiers please refer to the SDP REST API guide.

### Notes on field values
1. If a field value is an instance of `RestObject`, it is converted to its reference url and `.ref` is added to the field name.
   This allows native usage of `RestObject` in your code, i.e. `ep.search("hosts", host_group=hg)`
1. If a field value is instance of `ResultSet`, `list` or `tuple`, then list elements are converted to string by comma-joining
   and `__in` is added to the field name. This allows doing things like
   `ep.search("hosts", host_group=[hg1, hg2])`

## Working with `ResultSet`s
`ResultSet`s are returned by the  `.search()` method of `KrestEndPoint`. The number of results returned from the API 
is limited to 100. You can check the total number of results matching your search query
by inspecting the `.total` attribute of the result set.

For queries matching a large number of objects, you can use `__limit` and `__offset` query
parameters to fetch results by chunks.

**NOTE:** Its crucial to sort results to retrieve
objects in predictable order (use the `__sort` and `__sort_order` query attributes). All objects have an `id` field, to it is a good candidate to be used as a sorting field.

`ResultSet` is iterable, i.e. `for r in rv:...` is similar to
`for r in rv.hits:...`. It also supports `len(rv)` and *truthy* evaluation.

If you set the `.autofetch` attribute of a `ResultSet` object to 'true' before iterating it,
it will automatically fetch the next chunk of objects when the current chunk is 
exhausted. Don't forget to apply the sorting (as in the above note).


## Deleting objects
Once you have a `RestObject` at hand, simply call its `.delete()` method to delete it.

# More examples for object creation and manipulation


**NOTE:** All sizes in our SDP REST API are in kilobytes, with performance data being
the only exception - it returns results in bytes.

Create a volume-group
```
vg = ep.new("volume_groups", name="vg1", quota=100*2**20)
vg.capacity_policy = ep.search("vg_capacity_policies").hits[0]  # search ad-hoc
vg.save()
```

Create a volume in the above volume-group
```
vol = ep.new("volumes", name="v1", size=10*2**20, volume_group=vg).save()
```

Map a volume to a host-group
```
mapping = ep.new("mappings", volume=vol, host=hg)
mapping.save()
```

LUN editing is easy:
```
mapping.lun += 10
mapping.save()
```

Map a volume to a host
```
host2 = ep.new("hosts", name="standalone", type="Linux").save()
mapping = ep.new("mappings", volume=vol, host=host2).save()
```

Create a snapshot
```
snap = ep.new("snapshots")
snap.source = vg
snap.retention_policy = ep.search("retention_policies").hits[0]
snap.short_name = "s1"   # Note - use short_name, and not just name
snap.save()
```

Create a replica from the snapshot and map it
```
rep = ep.new("snapshots")
rep.source = snap
rep.short_name = "r1"
rep.retention_policy = ep.search("retention_policies").hits[0]
rep.is_exposable = True
rep.save()
mapping = ep.new("mappings", volume=rep, host=hg).save()
```

Restoring a volume-group from a snap is a breeze:
```
vg.last_restored_from = snap
vg.save()
```
