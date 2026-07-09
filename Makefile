
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O3
LDFLAGS = -lpcap -pthread

TARGET = packet_parser
SRC = packet_parser.cpp

# Default build rule
all: $(TARGET)

# Compile the target
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Clean compiled files
clean:
	rm -f $(TARGET)
