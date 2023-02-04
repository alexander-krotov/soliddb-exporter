CFLAGS = -g
CXXFLAGS = -g

solid-exporter: solid-exporter.o
	$(CC) -o $@ $< -lmicrohttpd sacl2x6470.so

soliddb-exporter: soliddb-exporter.o
	$(CXX) -o $@ $< -lmicrohttpd sacl2x6470.so

clean:
	rm -f solid-exporter
	rm -f *.o
