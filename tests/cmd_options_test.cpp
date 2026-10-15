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
    char *args[] = {"name.exe", "--command=encrypt", "--input=data", "--output=data", "--password=data"};
    EXPECT_NO_THROW(opt.Parse(std::size(args), args));
    ASSERT_EQ(opt.GetInputFile(), "data");
    ASSERT_EQ(opt.GetOutputFile(), "data");
    ASSERT_EQ(opt.GetPassword(), "data");
    ASSERT_EQ(opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, ArgsWithSpace) {
    CryptoGuard::ProgramOptions opt;
    char *args[] = {"name.exe", "--command=decrypt", "--input=da ta", "--output=da ta", "--password=da ta"};
    EXPECT_NO_THROW(opt.Parse(std::size(args), args));
    ASSERT_EQ(opt.GetInputFile(), "da ta");
    ASSERT_EQ(opt.GetOutputFile(), "da ta");
    ASSERT_EQ(opt.GetPassword(), "da ta");
    ASSERT_EQ(opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptions, ArgsRussian) {
    CryptoGuard::ProgramOptions opt;
    char *args[] = {"name.exe", "--command=checksum", "--input=вход", "--output=выход", "--password=пароль"};
    EXPECT_NO_THROW(opt.Parse(std::size(args), args));
    ASSERT_EQ(opt.GetInputFile(), "вход");
    ASSERT_EQ(opt.GetOutputFile(), "выход");
    ASSERT_EQ(opt.GetPassword(), "пароль");
    ASSERT_EQ(opt.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, ArgsEmpty) {
    CryptoGuard::ProgramOptions opt;
    char *args[] = {"name.exe"};
    ASSERT_ANY_THROW(opt.Parse(std::size(args), args));
}