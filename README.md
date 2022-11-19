# soliddb-exporter
SolidDb pmons exporter for Prometheus

Simple http daemon, listening on specified port (default is 9101) and when requested connecting to soliddb, reading the pmons, and converting them to a Prometheus format.

SolidDb pmons are SollidDb proprietary performance monitoring mechanism, it is very similar to what Prometheus would expect as
an input. SolidDb soes have direct http access, but does not allow direct queries from Prometheus.

Code uses microhttpd (version 0.9.75 used) and Solid ODBC library.

Command-line options:
```
solid-exporter [port] [connect-string] [user] [password]
```
- port is the port number where the daeomon in listening (default is 9001)
- connect-string is ODBC connect string in SoidDb format (default is "tcp 1964")
- ODBC user name (default is "dba")
- ODBC password (default is "dba")

To access pmons through this exporter add following to the prometheus config file:
```
  - job_name: solid
    # If soliddb-exporter is installed, grab stats about the local
    # machine by default.
    static_configs:
      - targets: ['localhost:9101']
```

Note: when using this deamon as is the user name and password do show in the process list. Process needs to be wrapped to a container, or the code should be changed to read the configuration from a config file.

Links:
- Prometheus: https://prometheus.io/
- Microhttpd: https://github.com/zorxx/microhttpd
- SolidDb: https://www.teamblue.unicomsi.com/products/soliddb/
- SolidDb pmons: https://support.unicomsi.com/manuals/soliddb/101/index.html#page/Administrator_Guide%2F5_Monitoring.06.27.html%23ww1138785
