#include "cmd_options.h"
#include <gtest/gtest.h>
#include <iterator>

TEST(ProgramOptions, ArgvNull) {
    CryptoGuard::ProgramOptions opt;
    ASSERT_ANY_THROW(opt.Parse(0, NULL));
}

TEST(ProgramOptions, ArgvPointerToNull) {
    CryptoGuard::ProgramOptions opt;
    char *argv = NULL;
    ASSERT_ANY_THROW(opt.Parse(0, &argv));
}

TEST(ProgramOptions, CheckArgs) {
    CryptoGuard::ProgramOptions opt;
    char *args[] = {"name.exe", "--command=encrypt", "--input=dataIn", "--output=dataOut", "--password=data"};
    EXPECT_NO_THROW(opt.Parse(std::size(args), args));
    ASSERT_EQ(opt.GetInputFile(), "dataIn");
    ASSERT_EQ(opt.GetOutputFile(), "dataOut");
    ASSERT_EQ(opt.GetPassword(), "data");
    ASSERT_EQ(opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, ArgsWithSpace) {
    CryptoGuard::ProgramOptions opt;
    char *args[] = {"name.exe", "--command=decrypt", "--input=da taIn", "--output=da taOut", "--password=da ta"};
    EXPECT_NO_THROW(opt.Parse(std::size(args), args));
    ASSERT_EQ(opt.GetInputFile(), "da taIn");
    ASSERT_EQ(opt.GetOutputFile(), "da taOut");
    ASSERT_EQ(opt.GetPassword(), "da ta");
    ASSERT_EQ(opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptions, ArgsRussian) {
    CryptoGuard::ProgramOptions opt;
    char *args[] = {"name.exe", "--command=decrypt", "--input=вход", "--output=выход", "--password=пароль"};
    EXPECT_NO_THROW(opt.Parse(std::size(args), args));
    ASSERT_EQ(opt.GetInputFile(), "вход");
    ASSERT_EQ(opt.GetOutputFile(), "выход");
    ASSERT_EQ(opt.GetPassword(), "пароль");
    ASSERT_EQ(opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptions, ArgsEmpty) {
    CryptoGuard::ProgramOptions opt;
    char *args[] = {"name.exe"};
    ASSERT_ANY_THROW(opt.Parse(std::size(args), args));
}

TEST(ProgramOptions, CheckInputEqOuput) {
    CryptoGuard::ProgramOptions opt;
    char *args[] = {"name.exe", "--command=encrypt", "--input=data", "--output=data", "--password=data"};
    ASSERT_ANY_THROW(opt.Parse(std::size(args), args));
}

TEST(ProgramOptions, CheckCheckSum) {
    CryptoGuard::ProgramOptions opt;
    char *args[] = {"name.exe", "--command=checksum", "--input=data"};
    ASSERT_NO_THROW(opt.Parse(std::size(args), args));
}

TEST(ProgramOptions, PrintHelp) {
    CryptoGuard::ProgramOptions opt;
    char *args[] = {"name.exe", "--help"};
    ASSERT_NO_THROW(opt.Parse(std::size(args), args));
}