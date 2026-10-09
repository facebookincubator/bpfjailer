// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sstream>
#include <string>
#include <string_view>

// A small gtest-shaped harness for the open source jailer, rather than gtest,
// because every test wants a bpffs of its own to pin into. Each TEST body runs
// in a forked child with its own mount namespace, so tests cannot collide on a
// pin path and a failed assertion can simply end the process.
//
// Running the tests needs root: mounting a bpffs is not permitted in an
// unprivileged user namespace.
//
// Tests run one at a time by default because repeatedly detaching several BPF
// trees at once can trigger kernel bugs. `-j N` or BPFJTEST_JOBS opts into
// parallel execution on a disposable VM. A task no tree enrolled has no
// task-storage entry, so one test's enforcers normally ignore another's
// processes when parallel execution is enabled.
//
// TEST_EXCLUSIVE is the way out for a test where that does not hold. Exec time
// enrollment is the case that breaks it: bpfj_enroll_from_xattr makes *every*
// loaded tree read BPFJ_EXEC_POLICY_XATTR off a binary and enroll it, so a
// fixture carrying a role another test also names gets pulled into that test's
// tree and judged by its policy. Anything asserting on state it does not own
// wants the same treatment.

namespace bpfjailer::test {

using TestBody = void (*)();

/// @brief Add a test to the registry, as the TEST macro does before main().
/// `exclusive` runs it alone, after every shared test has finished.
bool registerTest(
    const char* suite,
    const char* name,
    TestBody body,
    bool exclusive);

/// @brief The bpffs mount the running test has to itself, valid only inside a
/// test body.
const std::string& bpffsPath();

/// @brief A writable ext4 filesystem shared by the whole run, valid only
/// inside a test body, for a test needing what the bpffs lacks -- fs-verity,
/// which tmpfs cannot do and which cannot be undone.
///
/// Shared rather than one per test because the loop device under it cannot be
/// namespaced: Linux has no namespace for block devices, and one per test
/// churned 36 of the host's global pool of 128 a run and raced itself for the
/// next free number. Take a directory of your own inside it and stay there.
///
/// An ext4 image on a loop device, backed by a file in the harness's run-root
/// tmpfs and mounted in the harness's mount namespace, so the harness ending
/// unwinds the lot and nothing has to be deleted.
const std::string& scratchFsPath();

/// @brief Whether `path` exists.
[[nodiscard]] bool exists(const std::string& path);

/// @brief Leave context for fail() to print if this test goes on to fail, for
/// a helper that knows something the assertion cannot see -- `ctl()` uses it
/// for the stderr of a bpfjctl that exited non-zero. Last one wins.
void noteDiagnostic(std::string text);

/// @brief Report a failed assertion and end the test.
[[noreturn]] void fail(
    const char* file,
    int line,
    std::string_view expression,
    std::string_view detail = {});

/// @brief Run the selected registered tests, `jobs` of the shared ones at a
/// time. An empty selection runs all tests; otherwise it names a suite or a
/// suite and test separated by a dot.
/// @return the process exit status.
int runAll(int jobs, std::string_view selection = {});

/// @brief How many tests to run at once, from BPFJTEST_JOBS or a default.
[[nodiscard]] int defaultJobs();

namespace detail {

/// @brief Render the two sides of a comparison for a failure message.
template <typename L, typename R>
std::string describe(const L& lhs, const R& rhs) {
  std::ostringstream out;
  out << "      lhs was " << lhs << "\n      rhs was " << rhs;
  return out.str();
}

} // namespace detail

} // namespace bpfjailer::test

#define BPFJ_TEST_IMPL(suite, name, exclusive)                         \
  static void bpfjTestBody_##suite##_##name();                         \
  [[maybe_unused]] static const bool bpfjTestReg_##suite##_##name =    \
      ::bpfjailer::test::registerTest(                                 \
          #suite, #name, &bpfjTestBody_##suite##_##name, (exclusive)); \
  static void bpfjTestBody_##suite##_##name()

#define TEST(suite, name) BPFJ_TEST_IMPL(suite, name, false)

/// @brief A test that cannot share the host with another. See Harness.h's
/// header for what makes a test need this; say why at every use.
#define TEST_EXCLUSIVE(suite, name) BPFJ_TEST_IMPL(suite, name, true)

#define ASSERT(cond)                                                    \
  do {                                                                  \
    if (!(cond)) {                                                      \
      ::bpfjailer::test::fail(__FILE__, __LINE__, "ASSERT(" #cond ")"); \
    }                                                                   \
  } while (false)

#define ASSERT_EQ(lhs, rhs)                                                   \
  do {                                                                        \
    const auto& bpfjAssertLhs = (lhs);                                        \
    const auto& bpfjAssertRhs = (rhs);                                        \
    if (!(bpfjAssertLhs == bpfjAssertRhs)) {                                  \
      ::bpfjailer::test::fail(                                                \
          __FILE__,                                                           \
          __LINE__,                                                           \
          "ASSERT_EQ(" #lhs ", " #rhs ")",                                    \
          ::bpfjailer::test::detail::describe(bpfjAssertLhs, bpfjAssertRhs)); \
    }                                                                         \
  } while (false)

#define ASSERT_TRUE(cond) ASSERT(cond)
#define ASSERT_FALSE(cond) ASSERT(!(cond))
#define ASSERT_NE(lhs, rhs) ASSERT((lhs) != (rhs))
#define ASSERT_LT(lhs, rhs) ASSERT((lhs) < (rhs))
#define ASSERT_GT(lhs, rhs) ASSERT((lhs) > (rhs))
#define ASSERT_GE(lhs, rhs) ASSERT((lhs) >= (rhs))
#define ASSERT_LE(lhs, rhs) ASSERT((lhs) <= (rhs))

/// @brief Assert an Expected<> holds a value, reporting its error if not.
#define ASSERT_OK(expr)                                \
  do {                                                 \
    auto bpfjAssertRes = (expr);                       \
    if (!bpfjAssertRes) {                              \
      ::bpfjailer::test::fail(                         \
          __FILE__,                                    \
          __LINE__,                                    \
          "ASSERT_OK(" #expr ")",                      \
          "      " + bpfjAssertRes.error().message()); \
    }                                                  \
  } while (false)
