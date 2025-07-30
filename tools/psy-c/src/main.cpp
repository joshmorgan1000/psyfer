/**
 * @file main.cpp
 * @brief Main entry point for psy-c compiler
 */

#include "psy-c/parser.hpp"
#include "psy-c/code_generator.hpp"
#include "psy-c/impl_generator.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>

namespace fs = std::filesystem;

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " [options] <input.psy>\n";
    std::cerr << "\nOptions:\n";
    std::cerr << "  -o <file>     Output file (default: <input>.hpp)\n";
    std::cerr << "  --cpp <file>  Output implementation file (default: <input>.cpp)\n";
    std::cerr << "  -n <ns>       Add namespace prefix\n";
    std::cerr << "  --no-comments Don't generate doxygen comments\n";
    std::cerr << "  --exceptions  Use exceptions instead of error codes\n";
    std::cerr << "  -h, --help    Show this help message\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Parse command line arguments
    std::string input_file;
    std::string output_file;
    std::string impl_file;
    psyc::GeneratorOptions options;
    
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (std::strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (std::strcmp(argv[i], "--cpp") == 0 && i + 1 < argc) {
            impl_file = argv[++i];
        } else if (std::strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            options.namespace_prefix = argv[++i];
        } else if (std::strcmp(argv[i], "--no-comments") == 0) {
            options.generate_comments = false;
        } else if (std::strcmp(argv[i], "--exceptions") == 0) {
            options.use_exceptions = true;
        } else if (argv[i][0] != '-') {
            if (input_file.empty()) {
                input_file = argv[i];
            } else {
                std::cerr << "Error: Multiple input files specified\n";
                return 1;
            }
        } else {
            std::cerr << "Error: Unknown option: " << argv[i] << "\n";
            return 1;
        }
    }
    
    if (input_file.empty()) {
        std::cerr << "Error: No input file specified\n";
        print_usage(argv[0]);
        return 1;
    }
    
    // Determine output files
    fs::path input_path(input_file);
    if (output_file.empty()) {
        output_file = input_path.replace_extension(".hpp").string();
    }
    if (impl_file.empty()) {
        impl_file = input_path.replace_extension(".cpp").string();
    }
    
    try {
        // Parse the schema
        std::cout << "Parsing " << input_file << "...\n";
        auto schema = psyc::Parser::parse_file(input_file);
        
        // Set output header file for implementation
        options.output_header_file = fs::path(output_file).filename().string();
        
        // Generate header code
        std::cout << "Generating C++ header...\n";
        std::string header_code = psyc::CodeGenerator::generate(*schema, options);
        
        // Generate implementation code
        std::cout << "Generating C++ implementation...\n";
        std::string impl_code = psyc::ImplGenerator::generate(*schema, options);
        
        // Write header
        std::ofstream header_out(output_file);
        if (!header_out) {
            std::cerr << "Error: Cannot create output file: " << output_file << "\n";
            return 1;
        }
        header_out << header_code;
        header_out.close();
        
        // Write implementation
        std::ofstream impl_out(impl_file);
        if (!impl_out) {
            std::cerr << "Error: Cannot create output file: " << impl_file << "\n";
            return 1;
        }
        impl_out << impl_code;
        impl_out.close();
        
        std::cout << "Generated " << output_file << " and " << impl_file << "\n";
        
    } catch (const psyc::ParseError& e) {
        std::cerr << "Parse error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}