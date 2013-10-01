all: release

release:
	g++ test_analyzer.cpp -shared -fPIC -I../../src/api/
	mkdir -p ../../release
	mv a.out ../../release/libtestplugin.so

debug:
	g++ test_analyzer.cpp -shared -fPIC -g -O0 -I../../src/api/
	mkdir -p ../../debug
	mv a.out ../../debug/libtestplugin_d.so

clean:
	rm -Rf ../../{debug/libtestplugin_d.so,release/libtestplugin.so}
