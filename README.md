dlz-mysql-dynamic
==================

A Bind 9 Dynamically Loadable MySQL Driver

Summary
-------

This is an attempt to port the original Bind 9 DLZ dlz_mysql_driver.c as
found in the Bind 9 source tree into the new DLZ dlopen driver API.
The goals of this project are as follows:

* Provide DLZ facilities to OEM-supported Bind distributions
* Support both v1 (Bind 9.8) and v2 (Bind 9.9) of the dlopen() DLZ API

Requirements
------------

You will need the following:
 * Bind 9.8 or higher with the DLZ dlopen driver enabled
 * MySQL client libraries and source headers
 * A C compiler

Installation
------------

With the above requirements satisfied perform the following steps:

1. Ensure the symlink for dlz_minimal.h points at the correct header
   file matching your Bind version
2. Run: make
3. Run: sudo make install # this will install dlz_mysql_dynamic.so
   into /usr/lib/bind9/
4. Add a DLZ statement similar to the example shown in
   example/dlz.conf into your Bind configuration
5. Create a MySQL database and schema to support your data XXX UPDATE ME XXX   
6. If you're running an AppArmor enabled Bind, consider adding content
   included within example/apparmor.d-local-usr.sbin.named within
   /etc/apparmor.d/local/usr.sbin.named
7. Use the included testing/mysql-populate.pl script to provide some
   data for initial testing XXX UPDATE ME XXX

Usage
-----

Example usage is as follows:

```
dlz "mysql_dynamic" {
        database "dlopen /usr/lib/bind9/dlz_mysql_dynamic.so 
        {host=localhost dbname=dns_data ssl=true}
        {select zone from dns_records where zone = '%zone%'}
        {select ttl, type, mx_priority, case when lower(type)='txt' then concat('\"', data, '\"')
           when lower(type) = 'soa' then concat_ws(' ', data, resp_person, serial, refresh, retry, expire, minimum)
           else data end from dns_records where zone = '%zone%' and host = '%record%'}
        {select ttl, type, host, mx_priority, data, resp_person, serial, refresh, retry, expire, minimum 
                from dns_records where zone = '%zone%' and not (type = 'SOA' or type = 'NS')}
        {select ttl, type, host, mx_priority, case when lower(type)='txt' then
           concat('\"', data, '\"') else data end, resp_person, serial, refresh, retry, expire,
           minimum from dns_records where zone = '%zone%'}
        {select zone from xfr_table where zone = '%zone%' and client = '%client%'}
        {update data_count set count = count + 1 where zone ='%zone%'}";
};
```

The arguments for the "database" line above are as follows:

1. dlopen - Use the dlopen DLZ driver to dynamically load our compiled
   driver
2. The full path to your built dlz_mysql_dynamic.so
3. Connection options for this MySQL connection, supported options:
   - dbname
   - port
   - host
   - user
   - pass
   - socket
   - compress
   - ssl
   - space
4. Query to ascertain whether we host this zone - used by findzone() - Required
5. Query to find individual record(s) - used by lookup() - Required
6. Query to satisfy authority section lookups - used by authority() - Optional
7. Query to find all records for a zone - used by allnodes() - Optional
8. Query to establish whether a client is authorised to perform - Optional
   zone-transfer, requires prior query to be specified to work. - Optional
9. Query to update a counter of queries performed against a given zone - Optional

A copy of the above Bind configuration is included within
example/dlz.conf.

Author
------

The person responsible for this is:

 Mark Goldfinch <g@g.org.nz>

Original license conditions from both dlz_mysql_driver.c and
dlz_example.c are maintained in dlz_mysql_dynamic.c.
