PROJECT:=../../src

SOURCES:= \
	main.cpp \
	$(PROJECT)/controller/controller.cpp \
	$(PROJECT)/controller/cmdline_args.cpp \
	$(PROJECT)/filter/pcap/packet_reader.cpp \
	$(PROJECT)/filter/pcap/packet_capture.cpp \
	$(PROJECT)/program_options/configparser.cpp \
	$(PROJECT)/program_options/CmdLineParser.cpp \
	$(PROJECT)/program_options/ProgramOptions.cpp \

LIBS:= \
	-lpthread \
	-lpcap \

FLAGS:= \
	-O3 \
	-g \

thread:	$(SOURCES)
	g++ -o thread -I$(PROJECT) $(SOURCES) $(LIBS) $(FLAGS)

clean:
	rm -Rf thread
