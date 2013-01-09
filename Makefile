
.PHONY: nfstrace
nfstrace: nfstrace.cpp tcp_ip_headers.h
	g++ -O3 -lpcap -lpthread -o nfstrace nfstrace.cpp tcp_ip_headers.h nfs.h

.PHONY: clean
clean:
	@rm -f nfstrace
