
.PHONY: nfstrace
nfstrace: nfstrace.cpp tcp_ip_headers.h
	g++ -O3 -lpcap -o nfstrace nfstrace.cpp tcp_ip_headers.h

.PHONY: clean
clean:
	@rm -f nfstrace
