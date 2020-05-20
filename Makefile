
TARGET=lupcapd
OBJS=main.o lupcapd.o
#CXXFLAGS+=-I../../android/sysroot/include
#LDFLAGS+=-L../../android/sysroot/lib
LDLIBS+=-lpcap

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

main.o: main.cpp lupcapd.h
lupcapd.o: lupcapd.cpp

clean:
	rm -f $(TARGET)
	rm -f *.o