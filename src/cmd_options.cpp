#include "cmd_options.h"
#include <iostream>
#include <stdexcept>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
        ("help", "produce help message")
        ("command", boost::program_options::value<std::string>()->required(), "the encrypt, decrypt, or checksum command")
        ("input", boost::program_options::value<std::string>()->required(), "path to the input file")
        ("output", boost::program_options::value<std::string>(), "the path to the file where the result will be saved")
        ("password", boost::program_options::value<std::string>(), "password for encryption and decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm);

    if (vm.count("help")) {
        desc_.print(std::cout);
        return;
    }
    
    boost::program_options::notify(vm);

    auto it = std::find_if(std::begin(commandMapping_), std::end(commandMapping_),
                           [name = vm["command"].as<std::string>()](const auto &p) { return p.first == name; });

    if (it == std::end(commandMapping_)) {
        throw std::runtime_error("The command parameter can only be \"encrypt\", \"decrypt\", \"checksum\"");
    }

    command_ = it->second;
    
    inputFile_ = vm["input"].as<std::string>();

    if (GetCommand() != COMMAND_TYPE::CHECKSUM) {
        
        if (vm["output"].empty()) {
            throw std::runtime_error("output is empty");
        }
        outputFile_ = vm["output"].as<std::string>();

        if (vm["password"].empty()) {
            throw std::runtime_error("password is empty");
        }
        password_ = vm["password"].as<std::string>();

        if (outputFile_ == inputFile_) {
            throw std::runtime_error("outputFile_ == inputFile_");
        }
    }
}

}  // namespace CryptoGuard
