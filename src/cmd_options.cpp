#include "cmd_options.h"
#include <iostream>
#include <stdexcept>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    auto opt = desc_.add_options();
    opt("help", "produce help message");
    opt("command", boost::program_options::value<std::string>(), "the encrypt, decrypt, or checksum command");
    opt("input", boost::program_options::value<std::string>(), "path to the input file");
    opt("output", boost::program_options::value<std::string>(), "the path to the file where the result will be saved");
    opt("password", boost::program_options::value<std::string>(), "password for encryption and decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm);
    boost::program_options::notify(vm);

    if (vm.count("help")) {
        desc_.print(std::cout);
        return;
    }
    auto it = std::find_if(std::begin(commandMapping_), std::end(commandMapping_),
                           [name = vm["command"].as<std::string>()](const auto &p) { return p.first == name; });

    if (it == std::end(commandMapping_)) {
        throw std::runtime_error("The command parameter can only be \"encrypt\", \"decrypt\", \"checksum\"");
    }

    command_ = it->second;
    inputFile_ = vm["input"].as<std::string>();
    outputFile_ = vm["output"].as<std::string>();
    password_ = vm["password"].as<std::string>();
}

}  // namespace CryptoGuard
