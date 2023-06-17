#include "editor.h"
#include <stdlib.h>
#include <sys/mman.h>
#include <fstream>
#include <string>
#include "gtest/gtest.h"

constexpr char kMultilineTestContent[] = R"(first row
second row
third row
)";

// Function that creates a random string of ASCII characters
std::string RandomString(const uint64_t len) {
    std::string ascii =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string ret;

    int pos;
    while (ret.size() != len) {
        pos = ((rand() % (ascii.size() - 1)));
        ret += ascii.substr(pos, 1);
    }

    return ret;
}

void SetupState(State* state) {
    state->cx = 0;
    state->cy = 0;
    state->rowoff = 0;
    state->coloff = 0;
    state->numrows = 0;
    state->row = NULL;
    state->dirty = 0;
    state->filename = NULL;
    state->syntax = NULL;
}

void WriteTestFile(std::string filename, std::string content) {
    std::ofstream file;
    file.open(filename);
    file << content;
    file.close();
}

void CleanupTestFile(std::string filename) {
    std::remove(filename.c_str());
}

class EditorFixture : public ::testing::Test {
   public:
    void SetUp() {
        state_ = new State();
        SetupState(state_);

        std::string test_name =
            ::testing::UnitTest::GetInstance()->current_test_info()->name();
        std::cout << test_name << std::endl;

        test_fd_ = memfd_create(test_id_.data(), 0);
        test_id_ = RandomString(42);
        test_filename_ = test_name + test_id_;
        CleanupTestFile(test_filename_);

        WriteTestFile(test_filename_, std::string(kMultilineTestContent));
        Open(state_, test_filename_.data());
    }

    void TearDown() {
        CleanupTestFile(test_filename_);
        delete state_;
    }

    State* state_;
    int test_fd_;
    std::string test_id_;
    std::string test_filename_;
};

TEST_F(EditorFixture, OpenSetsRowState) {
    EXPECT_EQ(state_->numrows, 3);
    EXPECT_EQ(state_->row[0].chars, std::string("first row"));
    EXPECT_EQ(state_->row[1].chars, std::string("second row"));
    EXPECT_EQ(state_->row[2].chars, std::string("third row"));

    EXPECT_EQ(state_->row[0].size, 9);
    EXPECT_EQ(state_->row[1].size, 10);
    EXPECT_EQ(state_->row[2].size, 9);
}

TEST_F(EditorFixture, OpenSetsRowRender) {
    EXPECT_EQ(state_->row[0].render, std::string("first row"));
    EXPECT_EQ(state_->row[1].render, std::string("second row"));
    EXPECT_EQ(state_->row[2].render, std::string("third row"));

    EXPECT_EQ(state_->row[0].rsize, 9);
    EXPECT_EQ(state_->row[1].rsize, 10);
    EXPECT_EQ(state_->row[2].rsize, 9);
}

TEST_F(EditorFixture, InsertCharacter_FirstRow) {
    InsertChar(state_, std::string("a").data()[0]);

    EXPECT_EQ(state_->row[0].chars, std::string("afirst row"));
    EXPECT_EQ(state_->row[1].chars, std::string("second row"));
    EXPECT_EQ(state_->row[2].chars, std::string("third row"));
}

TEST_F(EditorFixture, ArrowRight_InsertCharacter) {
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);

    InsertChar(state_, std::string("a").data()[0]);

    EXPECT_EQ(state_->row[0].chars, std::string("fairst row"));
    EXPECT_EQ(state_->row[1].chars, std::string("second row"));
    EXPECT_EQ(state_->row[2].chars, std::string("third row"));
}

TEST_F(EditorFixture, ArrowDown_InsertCharacter) {
    ProcessKeyPress(test_fd_, state_, ARROW_DOWN);

    InsertChar(state_, std::string("a").data()[0]);

    EXPECT_EQ(state_->row[0].chars, std::string("first row"));
    EXPECT_EQ(state_->row[1].chars, std::string("asecond row"));
    EXPECT_EQ(state_->row[2].chars, std::string("third row"));
}

TEST_F(EditorFixture, ArrowDown_ArrowRight_InsertCharacter) {
    ProcessKeyPress(test_fd_, state_, ARROW_DOWN);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);

    InsertChar(state_, std::string("a").data()[0]);

    EXPECT_EQ(state_->row[0].chars, std::string("first row"));
    EXPECT_EQ(state_->row[1].chars, std::string("saecond row"));
    EXPECT_EQ(state_->row[2].chars, std::string("third row"));
}

TEST_F(EditorFixture, ArrowDown_ArrowRight_ArrowDown_InsertCharacter) {
    ProcessKeyPress(test_fd_, state_, ARROW_DOWN);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_DOWN);

    InsertChar(state_, std::string("a").data()[0]);

    EXPECT_EQ(state_->row[0].chars, std::string("first row"));
    EXPECT_EQ(state_->row[1].chars, std::string("second row"));
    EXPECT_EQ(state_->row[2].chars, std::string("tahird row"));
}

TEST_F(EditorFixture, Enter_Newline) {
    ProcessKeyPress(test_fd_, state_, ENTER);

    EXPECT_EQ(state_->row[0].chars, std::string(""));
    EXPECT_EQ(state_->row[1].chars, std::string("first row"));
    EXPECT_EQ(state_->row[2].chars, std::string("second row"));
    EXPECT_EQ(state_->row[3].chars, std::string("third row"));
}

TEST_F(EditorFixture, Enter_ArrowDown_Newline) {
    ProcessKeyPress(test_fd_, state_, ARROW_DOWN);
    ProcessKeyPress(test_fd_, state_, ENTER);

    EXPECT_EQ(state_->row[0].chars, std::string("first row"));
    EXPECT_EQ(state_->row[1].chars, std::string(""));
    EXPECT_EQ(state_->row[2].chars, std::string("second row"));
    EXPECT_EQ(state_->row[3].chars, std::string("third row"));
}

TEST_F(EditorFixture, Enter_EndOfRows_Newline) {
    ProcessKeyPress(test_fd_, state_, ARROW_DOWN);
    ProcessKeyPress(test_fd_, state_, ARROW_DOWN);
    ProcessKeyPress(test_fd_, state_, ARROW_DOWN);
    ProcessKeyPress(test_fd_, state_, ENTER);

    EXPECT_EQ(state_->row[0].chars, std::string("first row"));
    EXPECT_EQ(state_->row[1].chars, std::string("second row"));
    EXPECT_EQ(state_->row[2].chars, std::string("third row"));
    EXPECT_EQ(state_->row[3].chars, std::string(""));
}

TEST_F(EditorFixture, Backspace) {
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);

    EXPECT_EQ(state_->row[0].chars, std::string("first ro"));
    EXPECT_EQ(state_->row[1].chars, std::string("second row"));
    EXPECT_EQ(state_->row[2].chars, std::string("third row"));
}

TEST_F(EditorFixture, Backspace_ArrowDown) {
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_DOWN);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);

    EXPECT_EQ(state_->row[0].chars, std::string("first row"));
    EXPECT_EQ(state_->row[1].chars, std::string("second rw"));
    EXPECT_EQ(state_->row[2].chars, std::string("third row"));
}

TEST_F(EditorFixture, Backspace_RemoveRow) {
    ProcessKeyPress(test_fd_, state_, ARROW_DOWN);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, ARROW_RIGHT);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);
    ProcessKeyPress(test_fd_, state_, BACKSPACE);

    EXPECT_EQ(state_->numrows, 2);
    EXPECT_EQ(state_->row[0].chars, std::string("first row"));
    EXPECT_EQ(state_->row[1].chars, std::string("third row"));
}

TEST(Editor, Save_NoEncryption) {
    std::string test_filename = "/tmp/Save_" + RandomString(42);
    WriteTestFile(test_filename, std::string(""));
    State* state = new State();
    SetupState(state);

    Open(state, test_filename.data());

    InsertChar(state, std::string("a").data()[0]);
    Save(state);

    std::ifstream file(test_filename);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    EXPECT_EQ(content, std::string("a\n"));
    CleanupTestFile(test_filename);
}

TEST(Editor, E2E_Encryption_Empty) {
    std::string test_filename = "/tmp/E2E_Encryption_Empty.aes256cbc";
    CleanupTestFile(test_filename);

    State* state = new State();
    SetupState(state);

    // These keys correspond to:
    // test
    // [ENTER KEY]
    // test
    // [ENTER KEY]
    // hello
    const std::vector<int> new_file_keys = {116, 101, 115, 116, 13,
                                            116, 101, 115, 116, 13};
    // These keys correspond to:
    // test
    // [ENTER KEY]
    const std::vector<int> existing_file_keys = {116, 101, 115, 116, 13};

    HandleEncryption(state, test_filename.data(), new_file_keys);
    Open(state, test_filename.data());
    Save(state);
    EXPECT_EQ(state->password, std::string("test"));

    state = new State();
    SetupState(state);
    HandleEncryption(state, test_filename.data(), existing_file_keys);
    Open(state, test_filename.data());

    CleanupTestFile(test_filename);
}

TEST(Editor, E2E_Encryption_SingleLine) {
    std::string test_filename = "/tmp/E2E_Encryption_SingleLine.aes256cbc";
    std::string content = "hello";
    CleanupTestFile(test_filename);

    State* state = new State();
    SetupState(state);

    // These keys correspond to:
    // test
    // [ENTER KEY]
    // test
    // [ENTER KEY]
    // hello
    const std::vector<int> new_file_keys = {116, 101, 115, 116, 13,
                                            116, 101, 115, 116, 13};
    // These keys correspond to:
    // test
    // [ENTER KEY]
    const std::vector<int> existing_file_keys = {116, 101, 115, 116, 13};

    HandleEncryption(state, test_filename.data(), new_file_keys);
    Open(state, test_filename.data());
    InsertString(state, content);
    Save(state);
    EXPECT_EQ(state->password, std::string("test"));

    state = new State();
    SetupState(state);
    HandleEncryption(state, test_filename.data(), existing_file_keys);
    Open(state, test_filename.data());

    EXPECT_EQ(state->row[0].chars, std::string("hello"));
    CleanupTestFile(test_filename);
}

TEST(Editor, E2E_Encryption_MultiLine) {
    std::string test_filename = "/tmp/E2E_Encryption_SingleLine.aes256cbc";
    std::string first_line = "hello";
    std::string second_line = "world";
    CleanupTestFile(test_filename);

    State* state = new State();
    SetupState(state);

    // These keys correspond to:
    // test
    // [ENTER KEY]
    // test
    // [ENTER KEY]
    // hello
    const std::vector<int> new_file_keys = {116, 101, 115, 116, 13,
                                            116, 101, 115, 116, 13};
    // These keys correspond to:
    // test
    // [ENTER KEY]
    const std::vector<int> existing_file_keys = {116, 101, 115, 116, 13};

    HandleEncryption(state, test_filename.data(), new_file_keys);
    Open(state, test_filename.data());
    InsertString(state, first_line);
    ProcessKeyPress(0, state, ENTER);
    InsertString(state, second_line);
    Save(state);
    EXPECT_EQ(state->password, std::string("test"));

    state = new State();
    SetupState(state);
    HandleEncryption(state, test_filename.data(), existing_file_keys);
    Open(state, test_filename.data());

    EXPECT_EQ(state->row[0].chars, first_line);
    EXPECT_EQ(state->row[1].chars, second_line);
    CleanupTestFile(test_filename);
}

TEST(Editor, E2E_Encryption_SingleLine_Edit) {
    std::string test_filename = "/tmp/E2E_Encryption_SingleLine.aes256cbc";
    std::string content = "hello";
    std::string edit = "world";
    CleanupTestFile(test_filename);

    State* state = new State();
    SetupState(state);

    // These keys correspond to:
    // test
    // [ENTER KEY]
    // test
    // [ENTER KEY]
    // hello
    const std::vector<int> new_file_keys = {116, 101, 115, 116, 13,
                                            116, 101, 115, 116, 13};
    // These keys correspond to:
    // test
    // [ENTER KEY]
    const std::vector<int> existing_file_keys = {116, 101, 115, 116, 13};

    HandleEncryption(state, test_filename.data(), new_file_keys);
    Open(state, test_filename.data());
    InsertString(state, content);
    Save(state);
    EXPECT_EQ(state->password, std::string("test"));

    state = new State();
    SetupState(state);
    HandleEncryption(state, test_filename.data(), existing_file_keys);
    Open(state, test_filename.data());
    ProcessKeyPress(0, state, ARROW_RIGHT);
    ProcessKeyPress(0, state, ARROW_RIGHT);
    ProcessKeyPress(0, state, ARROW_RIGHT);
    ProcessKeyPress(0, state, ARROW_RIGHT);
    ProcessKeyPress(0, state, ARROW_RIGHT);
    InsertString(state, edit);
    Save(state);

    state = new State();
    SetupState(state);
    HandleEncryption(state, test_filename.data(), existing_file_keys);
    Open(state, test_filename.data());

    EXPECT_EQ(state->row[0].chars, std::string("helloworld"));
    CleanupTestFile(test_filename);
}
