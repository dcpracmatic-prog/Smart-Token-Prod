CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -fPIC
LDFLAGS =

libfriction.so: friction_core.cpp friction_core.hpp
	$(CXX) $(CXXFLAGS) -shared -o libfriction.so friction_core.cpp

demo: main_demo.cpp friction_core.cpp friction_core.hpp
	$(CXX) $(CXXFLAGS) -o friction_demo main_demo.cpp friction_core.cpp

all: libfriction.so demo

clean:
	rm -f libfriction.so friction_demo

.PHONY: all clean demo
