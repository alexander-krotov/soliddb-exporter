# soliddb-exporter
SolidDb pmons exporter for Prometheus

Simple http daemon, listening on specified port (defult is 9101) and when requested connecting to soliddb, reading the pmons, and converting them to a Prometeus format.
Code uses microhttpd (version 0.9.75 used).

