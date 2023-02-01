
CXX						= g++
STANDARD_FLAGS			= -std=c++20
CPPFLAGS             	= $(DEBUG_FLAGS) $(STANDARD_FLAGS) $(WARN_AS_ERRORS_FLAGS)

INCS 	= -Iinc
SRCS	= ./test/TestCppSocket.cpp

LIBS	= -lssl -lcrypto
TARGET	= testcppsocket

all: $(TARGET)
	echo $(TARGET) is created!

$(TARGET): $(SRCS)
	rm -f $(TARGET)
	$(CXX) $(CPPFLAGS) -o $(TARGET) $(INCS) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET)
