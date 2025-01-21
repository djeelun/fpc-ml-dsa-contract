# Compiler and flags
CXX := g++
CXXFLAGS := -I ../utils

# Source files
SRC := test_hex_utils.cpp ../utils/hexutils.cpp

# Output binary
TARGET := test_hex_utils.out

# Default target: Build and execute
all: $(TARGET)
	./$(TARGET)

# Build target
$(TARGET): $(SRC)
	$(CXX) -o $(TARGET) $(SRC) $(CXXFLAGS)

# Clean target to remove generated files
clean:
	rm -f $(TARGET)

.PHONY: all clean

