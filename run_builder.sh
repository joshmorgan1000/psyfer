#!/bin/bash
set -e

# Colors for output
RED='\033[1;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

IS_CLAUDE=OFF
if [[ "$PATH" == *"claudespace/spec"* ]]; then
    IS_CLAUDE=ON
fi

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    echo "Detected: macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo "Detected: Linux"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    OS="windows"
    echo "Detected: Windows"
fi

# Parse command line arguments
BUILD_TYPE="Release"
BUILD_DIR="build"
FORCE_CPU_ONLY=OFF
VERBOSE=OFF
TEST_NAME=""
RUN_ALL_TESTS=OFF
TEST_OPTIONS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --cpu-only)
            FORCE_CPU_ONLY=ON
            echo -e "${YELLOW}Forcing CPU-only build${NC}"
            shift
            ;;
        --log-level)
            if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
                LOG_LEVEL="$2"
                shift 2
            else
                echo -e "${RED}Invalid log level: $2${NC}"
                exit 1
            fi
            ;;
        --test)
            if [[ -n "$2" ]]; then
                # If an asterisk is provided, run all tests
                if [[ "$2" == "--all" ]]; then
                    RUN_ALL_TESTS=ON
                    echo -e "${YELLOW}Building and running all tests${NC}"
                    shift 2
                else
                    TEST_NAME="$2"
                    shift 2
                fi
                if [[ -n "$3" && "$3" == "--options" ]]; then
                    shift 2
                    TEST_OPTIONS="$1"
                    shift
                else
                    TEST_OPTIONS=""
                fi
            else
                echo -e "${RED}Error: --test option requires a test name or --all${NC}"
                exit 1
            fi
            ;;
        --verbose)
            VERBOSE=ON
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --debug"
            echo "               Build in debug mode"
            echo " "
            echo "  --log-level LEVEL"
            echo "               Set log level (default: 4)"
            echo " "
            echo "  --test [TEST_NAME | --all] [--options OPTIONS]"
            echo "               Build and run specific test or all tests,"
            echo "               with optional command line options to pass to the test"
            echo " "
            echo "  --cpu-only"
            echo "               Force CPU-only build (no GPU)"
            echo " "
            echo "  --verbose"
            echo "               Verbose output"
            echo " "
            echo "  --help"
            echo "               Show this help"
            echo " "
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done
# Echo the log level setting if set
if [[ -n "$LOG_LEVEL" ]]; then
    echo -e "${YELLOW}Log level set to: ${LOG_LEVEL}${NC}"
    # Set the log level for psyfer
    export psyfer_LOG_LEVEL="$LOG_LEVEL"
else
    # Default log level if not set
    export psyfer_LOG_LEVEL=4
    echo -e "${YELLOW}Building with default log level set for psyfer: ${psyfer_LOG_LEVEL}${NC}"
fi 
# Echo the verbose setting if it is enabled
if [[ "$VERBOSE" == "ON" ]]; then
    echo -e "${YELLOW}Verbose mode enabled${NC}"
fi
# Make sure we are in the project root directory (the same directory as this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -d "${SCRIPT_DIR}/include/inkpacket" ]]; then
    echo -e "${RED}Error: This script must be run from the project root directory.${NC}"
    exit 1
fi
export BUILD_DIR="/Users/joshmorgan/projects/encryption/psyfer/build"
if [[ -d "${BUILD_DIR}" ]]; then
    rm -rf "${BUILD_DIR}"
fi
# Create build directory
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}
# Configure with CMake
CMAKE_ARGS=(
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE}
    -Dpsyfer_FORCE_CPU_ONLY=${FORCE_CPU_ONLY}
    -Dpsyfer_BUILD_EXAMPLES=ON
    -Dpsyfer_BUILD_TESTS=ON
    -Dpsyfer_BUILD_BENCHMARKS=ON
    -Dpsyfer_LOG_LEVEL=${psyfer_LOG_LEVEL}
)
# Always use ninja if available
if command -v ninja &> /dev/null; then
    CMAKE_ARGS+=(-G Ninja)
    BUILD_COMMAND="ninja"
else
    echo -e "${YELLOW}WARNING: ninja not found. Trying make instead (may not work)${NC}"
    CMAKE_ARGS+=(-G "Unix Makefiles")
    BUILD_COMMAND="make"
fi
# Run CMake
if [[ "$VERBOSE" == "ON" ]]; then
    echo -e "${YELLOW}Configuring with CMake in verbose mode...${NC}"
    cmake "${CMAKE_ARGS[@]}" -DCMAKE_VERBOSE_MAKEFILE=ON ..
else
    printf "${YELLOW}Configuring with CMake...${NC}"
    PRINT_LINE_INFO=OFF
    CYAN_LINES=0
    PURPLE_LINES=0
    cmake "${CMAKE_ARGS[@]}" .. 2>&1 | while IFS= read -r line; do
        # Change the color to red for errors
        if [[ "$line" == *"_____  ______ __    _ ____   _  ______"* ]]; then
            PRINT_LINE_INFO=ON
            CYAN_LINES=4
            printf "\n"
        fi
        if [[ $CYAN_LINES -gt 0 ]]; then
            printf "${CYAN}${line}${NC}\n"
            CYAN_LINES=$((CYAN_LINES - 1))
            if [[ $CYAN_LINES -eq 0 ]]; then
                PURPLE_LINES=1
            fi
        elif [[ $PURPLE_LINES -gt 0 ]]; then
            printf "${PURPLE}${line}${NC}\n"
            PURPLE_LINES=$((PURPLE_LINES - 1))
        elif [[ "$PRINT_LINE_INFO" == "ON" ]]; then
            echo -e "${line}"
        else
            if [[ "$IS_CLAUDE" == "OFF" ]]; then
                printf "."
            fi
        fi
        echo "$line" >> cmake_psyfer.log
    done
fi
if grep -q "errors occurred!" cmake_psyfer.log; then
    echo -e "\n${RED}=== CMake Configuration Failed! ===${NC}"
    echo "  Build type: ${BUILD_TYPE}"
    echo -e "${NC}For more details, check the configuration log: ${BUILD_DIR}/cmake_psyfer.log"
    exit 1
else
    echo -e "\n${GREEN}=== CMake Configuration Complete ===${NC}"
    echo "  Build type: ${BUILD_TYPE}"
fi
# Build command
set +e  # Disable exit on error temporarily
printf "${YELLOW}Building...${NC}"
PRINT_ERROR_ON=OFF
if [[ "$VERBOSE" == "ON" ]]; then
    ${BUILD_COMMAND} 2>&1 | tee build_psyfer.log
else
    ${BUILD_COMMAND} 2>&1 | while IFS= read -r line; do
        # Change the color to red for errors
        if [[ "$line" == "FAILED:"* ]]; then
            PRINT_ERROR_ON=ON
            echo " " >> build_psyfer_errors.log
        elif [[ "$line" == *"linker command failed"* ]]; then
            PRINT_ERROR_ON=OFF
        elif [[ "$line" == "[\d]+ error[s]* generated[\.]"* ]]; then
            PRINT_ERROR_ON=OFF
        elif [[ "$line" == *"error[s]* generated"* ]]; then
            PRINT_ERROR_ON=OFF
        elif [[ "$line" == "[\[][\d]+/[\d]+[\]]"* ]]; then
            PRINT_ERROR_ON=OFF
        fi
        if [[ "$PRINT_ERROR_ON" == "ON" ]]; then
            echo "$line" >> build_psyfer_errors.log
        else
            if [[ "$IS_CLAUDE" == "OFF" ]]; then
                printf "."
            fi
        fi
        echo "$line" >> build_psyfer.log
    done
fi
set -e  # Re-enable exit on error
# Check if the error log file exists and has content
if [[ -s build_psyfer_errors.log ]]; then
    echo -e "\n${RED}=== Build Failed! ===${NC}"
    echo "  Build directory: $(pwd)"
    echo "  Build type: ${BUILD_TYPE}"
    echo -e "${NC}For more details, check the build log: ${BUILD_DIR}/build_psyfer.log"
    echo " "
    echo -e "${RED}Errors encountered during build:${NC}"
    cat build_psyfer_errors.log
    exit 1
else
    echo -e "\n${GREEN}=== Build Complete ===${NC}"
    echo "  Build directory: $(pwd)"
    echo "  Build type: ${BUILD_TYPE}"
    echo -e "${YELLOW}For more details, check the build log: ${BUILD_DIR}/build_psyfer.log${NC}"
fi 
# Run tests if specified
if [[ -n "$TEST_NAME" || "$RUN_ALL_TESTS" == "ON" ]]; then
    cd "${BUILD_DIR}/tests"
    if [[ "$RUN_ALL_TESTS" == "ON" ]]; then
        TESTS_FAILED=0
        TESTS_PASSED=0
        echo -e "\n${GREEN}Running all tests...${NC}"
        # List all the executables in the build/tests directory
        TEST_EXECUTABLES=$(find . -type f -executable -name "test_*" -o -name "test_*_test" | sort)
        set +e
        if [[ -z "$TEST_EXECUTABLES" ]]; then
            echo -e "${YELLOW}No tests found to run.${NC}"
        else
            for test in $TEST_EXECUTABLES; do
                echo -e "\n${YELLOW}Running test: $test${NC}"
                if [[ -n "$TEST_OPTIONS" ]]; then
                    echo -e "${YELLOW}With options: $TEST_OPTIONS${NC}"
                    ./"$test" $TEST_OPTIONS
                else
                    ./"$test"
                fi
                if [[ $? -ne 0 ]]; then
                    echo -e "${RED}Test $test failed!${NC}"
                    TESTS_FAILED=$((TESTS_FAILED + 1))
                    echo -e " "
                else
                    echo -e "${GREEN}Test $test passed!${NC}"
                    TESTS_PASSED=$((TESTS_PASSED + 1))
                    echo -e " "
                fi
            done
        fi
        set -e
        echo -e "\n${GREEN}=== All Tests Complete ===${NC}"
        echo "  Total tests run: $((TESTS_FAILED + TESTS_PASSED))"
        echo "  Tests passed: ${GREEN}$TESTS_PASSED${NC}"
        echo "  Tests failed: ${RED}$TESTS_FAILED${NC}"
    else
        echo -e "\n${YELLOW}Running test: $TEST_NAME${NC}"
        set +e
        if [[ -n "$TEST_OPTIONS" ]]; then
            echo -e "${YELLOW}With options: $TEST_OPTIONS${NC}"
            ./"$TEST_NAME" $TEST_OPTIONS
        else
            ./"$TEST_NAME"
        fi
        set -e
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}Test $TEST_NAME failed!${NC}"
        else
            echo -e "${GREEN}Test $TEST_NAME passed!${NC}"
        fi
    fi
    echo " "
fi
