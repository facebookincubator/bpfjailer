// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bpfj/lib/GlobMap.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/bpf/types_glob_map.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/glob_map_test.skel.h"
#include "tests/bpf/types_glob_map_test.h"

namespace {

using Skel = bpfj::libbpf::BpfSkel<glob_map_test_bpf>;
using Entries = std::vector<std::pair<std::string, std::uint64_t>>;

const bpfjailer::GlobKeyResolver kResolve =
    [](std::string_view name) -> bpfjailer::err::Expected<__u32> {
  if (name == "V") {
    return 1;
  }
  return bpfjailer::err::Error(
      std::errc::invalid_argument, "unknown test variable");
};

class GlobFixture {
 public:
  GlobFixture() {
    auto created = Skel::create();
    ASSERT_OK(created);
    skel_ = *created;
    ASSERT_OK(skel_->load());
    ASSERT_OK(bpfjailer::heap::init(skel_));

    run_ = bpfjailer::heap::alloc<struct bpfj_glob_run>(skel_);
    bindings_ = bpfjailer::heap::alloc<struct bpfj_glob_bindings>(skel_);
    input_ =
        bpfjailer::heap::allocArray<char>(skel_, BPFJ_GLOB_MAP_MAX_STR_LEN + 1);
    ASSERT(run_ != nullptr);
    ASSERT(bindings_ != nullptr);
    ASSERT(input_ != nullptr);
    bpfj_glob_run_init(run_);
    *bindings_ = {};

    skel_->bss().bpfj_glob_test_run = run_;
    skel_->bss().bpfj_glob_test_bindings = bindings_;
    map_ = std::make_unique<bpfjailer::GlobMap<Skel>>(
        skel_, skel_->bss().bpfj_glob_test_map);
  }

  ~GlobFixture() {
    map_->destroy();
  }

  bpfjailer::err::Expected<> init(
      Entries entries,
      bpfjailer::GlobKeyResolver resolve = kResolve) {
    return map_->init(std::move(resolve), std::move(entries));
  }

  void bind(__u32 key, std::string_view value, __u32 len) {
    ASSERT(value.size() <= BPFJ_GLOB_MAP_MAX_VAR_LEN);
    *bindings_ = {};
    bindings_->count = 1;
    bindings_->b[0].key = key;
    bindings_->b[0].len = len;
    std::memcpy(bindings_->b[0].val, value.data(), value.size());
  }

  void clearBindings() {
    *bindings_ = {};
  }

  std::size_t used() const {
    return bpfjailer::heap::currentUsed(skel_);
  }

  bool published() const {
    return skel_->bss().bpfj_glob_test_map != nullptr;
  }

  void destroy() {
    map_->destroy();
  }

  std::vector<std::uint64_t> lookup(std::string_view input) {
    ASSERT(input.size() <= BPFJ_GLOB_MAP_MAX_STR_LEN + 1);
    std::memcpy(input_, input.data(), input.size());
    const long count =
        run(bpfj_glob_test_req{
            .op = BPFJ_GLOB_TEST_LOOKUP,
            .input_off = bpfjailer::heap::ptrToOffset(
                bpfjailer::heap::base(skel_), input_),
            .len = static_cast<__u32>(input.size()),
        });
    ASSERT(count >= 0);

    std::vector<std::uint64_t> out;
    out.reserve(static_cast<std::size_t>(count));
    auto* values = static_cast<const __u64*>(run_->results.buf);
    for (long i = 0; i < count; ++i) {
      out.push_back(values[i]);
    }
    return out;
  }

  long lookupStatus(std::string_view input) {
    ASSERT(input.size() <= BPFJ_GLOB_MAP_MAX_STR_LEN + 1);
    std::memcpy(input_, input.data(), input.size());
    return run(
        bpfj_glob_test_req{
            .op = BPFJ_GLOB_TEST_LOOKUP,
            .input_off = bpfjailer::heap::ptrToOffset(
                bpfjailer::heap::base(skel_), input_),
            .len = static_cast<__u32>(input.size()),
        });
  }

  bool contains(std::string_view input, std::uint64_t wanted) {
    return containsStatus(input, wanted) == 1;
  }

  long containsStatus(std::string_view input, std::uint64_t wanted) {
    return runOnInput(input, BPFJ_GLOB_TEST_CONTAINS, wanted, 0, 0);
  }

  bool containsRange(std::string_view input, __u32 first, __u32 count) {
    return containsRangeStatus(input, first, count) == 1;
  }

  long containsRangeStatus(std::string_view input, __u32 first, __u32 count) {
    return runOnInput(input, BPFJ_GLOB_TEST_CONTAINS_RANGE, 0, first, count);
  }

 private:
  long runOnInput(
      std::string_view input,
      __u32 op,
      std::uint64_t wanted,
      __u32 first,
      __u32 count) {
    ASSERT(input.size() <= BPFJ_GLOB_MAP_MAX_STR_LEN + 1);
    std::memcpy(input_, input.data(), input.size());
    return run(
        bpfj_glob_test_req{
            .wanted = wanted,
            .op = op,
            .input_off = bpfjailer::heap::ptrToOffset(
                bpfjailer::heap::base(skel_), input_),
            .len = static_cast<__u32>(input.size()),
            .first = first,
            .count = count,
        });
  }

  long run(const bpfj_glob_test_req& req) {
    LIBBPF_OPTS(
        bpf_test_run_opts,
        opts,
        .ctx_in = const_cast<bpfj_glob_test_req*>(&req),
        .ctx_size_in = sizeof(req));
    const int fd = bpf_program__fd(skel_->progs().bpfj_glob_test);
    ASSERT(fd >= 0);
    ASSERT_EQ(bpf_prog_test_run_opts(fd, &opts), 0);
    return static_cast<std::int32_t>(opts.retval);
  }

  std::shared_ptr<Skel> skel_;
  struct bpfj_glob_run* run_ = nullptr;
  struct bpfj_glob_bindings* bindings_ = nullptr;
  char* input_ = nullptr;
  std::unique_ptr<bpfjailer::GlobMap<Skel>> map_;
};

void assertValues(
    const std::vector<std::uint64_t>& actual,
    std::initializer_list<std::uint64_t> expected) {
  ASSERT_EQ(actual.size(), expected.size());
  std::size_t at = 0;
  for (const auto value : expected) {
    ASSERT_EQ(actual[at], value);
    ++at;
  }
}

void assertErrorContains(
    const bpfjailer::err::Expected<>& result,
    std::string_view text) {
  ASSERT(!result);
  ASSERT(result.error().message().find(text) != std::string::npos);
}

std::string numberedPattern(std::size_t number) {
  std::string out(59, 'a');
  out.push_back(static_cast<char>('0' + ((number / 1000) % 10)));
  out.push_back(static_cast<char>('0' + ((number / 100) % 10)));
  out.push_back(static_cast<char>('0' + ((number / 10) % 10)));
  out.push_back(static_cast<char>('0' + (number % 10)));
  return out;
}

} // namespace

TEST(GlobMap, MatchesEmptyLiteralQuestionAndStarPatterns) {
  GlobFixture fixture;
  ASSERT_OK(fixture.init(
      {{"", 1}, {"abc", 2}, {"a?c", 3}, {"a*c", 4}, {"a**c", 5}, {"*", 6}}));

  assertValues(fixture.lookup(""), {1, 6});
  assertValues(fixture.lookup("abc"), {2, 3, 4, 5, 6});
  assertValues(fixture.lookup("abbc"), {4, 5, 6});
}

TEST(GlobMap, BackslashEscapesEveryMetacharacter) {
  GlobFixture fixture;
  ASSERT_OK(fixture.init(
      {{R"(\*)", 1}, {R"(\?)", 2}, {R"(\$)", 3}, {R"(\\)", 4}, {"\\", 5}}));

  assertValues(fixture.lookup("*"), {1});
  assertValues(fixture.lookup("?"), {2});
  assertValues(fixture.lookup("$"), {3});
  assertValues(fixture.lookup("\\"), {4, 5});
}

TEST(GlobMap, MatchesExplicitLengthBinaryBytes) {
  GlobFixture fixture;
  ASSERT_OK(fixture.init(
      {{std::string("a\0b", 3), 1}, {"a?b", 2}, {std::string("a\0c", 3), 3}}));

  const auto nulB = fixture.lookup(std::string("a\0b", 3));
  ASSERT(!nulB.empty());
  ASSERT_EQ(nulB.front(), 1U);
  assertValues(nulB, {1, 2});
  const auto nulC = fixture.lookup(std::string("a\0c", 3));
  ASSERT(!nulC.empty());
  ASSERT_EQ(nulC.front(), 3U);
  assertValues(nulC, {3});
}

TEST(GlobMap, VariablesSupportBoundEmptyAndPoisonedValues) {
  GlobFixture fixture;
  ASSERT_OK(fixture.init(
      {{"${V}", 1},
       {"pre-${V}-*", 2},
       {"literal", 3},
       {"*${V}", 4},
       {"${V}*", 5}}));

  fixture.clearBindings();
  assertValues(fixture.lookup(""), {1, 4, 5});
  fixture.bind(1, "abc", 3);
  assertValues(fixture.lookup("abc"), {1, 4, 5});
  assertValues(fixture.lookup("pre-abc-tail"), {2});
  assertValues(fixture.lookup("tailabc"), {4});
  assertValues(fixture.lookup("abctail"), {5});
  fixture.bind(1, "", BPFJ_GLOB_MAP_MAX_VAR_LEN + 1);
  assertValues(fixture.lookup(""), {});
  assertValues(
      fixture.lookup(std::string(BPFJ_GLOB_MAP_MAX_VAR_LEN, '\0')), {});
  assertValues(fixture.lookup("literal"), {3});
}

TEST(GlobMap, EmptyMapMatchesNothing) {
  GlobFixture fixture;
  ASSERT_OK(fixture.init({}));

  assertValues(fixture.lookup(""), {});
  assertValues(fixture.lookup("anything"), {});
}

TEST(GlobMap, ReinitializingReleasesThePreviousCompilation) {
  GlobFixture fixture;
  const auto baseline = fixture.used();
  ASSERT_OK(fixture.init({{"abc", 1}}));
  ASSERT(fixture.used() > baseline);

  ASSERT_OK(fixture.init({{"def", 2}, {"ghi", 3}}));
  fixture.destroy();
  ASSERT_EQ(fixture.used(), baseline);
}

TEST(GlobMap, FailedInitializationUnwindsPublishedState) {
  GlobFixture fixture;
  const auto baseline = fixture.used();

  const auto failed = fixture.init({{"a${NOPE}", 1}});
  ASSERT(!failed);
  ASSERT(!fixture.published());
  ASSERT_EQ(fixture.used(), baseline);

  ASSERT_OK(fixture.init({{"abc", 1}}));
  fixture.destroy();
  ASSERT_EQ(fixture.used(), baseline);
}

TEST(GlobMap, ReturnsEveryMatchPastTheFormerResultLimit) {
  Entries entries;
  for (std::uint64_t i = 0; i < 100; ++i) {
    entries.emplace_back("*", i + 1);
  }

  GlobFixture fixture;
  ASSERT_OK(fixture.init(std::move(entries)));
  const auto matches = fixture.lookup("anything");
  ASSERT_EQ(matches.size(), 100U);
  for (std::size_t i = 0; i < matches.size(); ++i) {
    ASSERT_EQ(matches[i], i + 1);
  }
}

TEST(GlobMap, ContainsAndContainsRangeIgnoreUnrelatedAccepts) {
  GlobFixture fixture;
  ASSERT_OK(fixture.init({{"a*", 1}, {"ab*", 2}, {"z*", 3}}));

  ASSERT(fixture.contains("abc", 2));
  ASSERT(!fixture.contains("abc", 3));
  ASSERT(fixture.containsRange("abc", 1, 1));
  ASSERT(!fixture.containsRange("abc", 2, 1));
  ASSERT(!fixture.containsRange("abc", 3, 1));
  ASSERT(!fixture.containsRange("abc", 4, 0));
  ASSERT(!fixture.containsRange("abc", 2, 2));
}

TEST(GlobMap, SupportsTheRaisedWordAndInputLimits) {
  Entries entries;
  for (std::uint64_t i = 0; i < 40; ++i) {
    entries.emplace_back(numberedPattern(i), i + 1);
  }
  entries.emplace_back("a*", 1000);

  GlobFixture fixture;
  ASSERT_OK(fixture.init(std::move(entries)));
  assertValues(fixture.lookup(numberedPattern(37)), {38, 1000});
  assertValues(
      fixture.lookup(std::string(BPFJ_GLOB_MAP_MAX_STR_LEN, 'a')), {1000});
  ASSERT_EQ(
      fixture.lookupStatus(std::string(BPFJ_GLOB_MAP_MAX_STR_LEN + 1, 'a')),
      -E2BIG);
  ASSERT_EQ(
      fixture.containsStatus(
          std::string(BPFJ_GLOB_MAP_MAX_STR_LEN + 1, 'a'), 1000),
      -E2BIG);
  ASSERT_EQ(
      fixture.containsRangeStatus(
          std::string(BPFJ_GLOB_MAP_MAX_STR_LEN + 1, 'a'), 0, 1),
      -E2BIG);
}

TEST(GlobMap, SupportsMoreThanTheFormerGadgetLimit) {
  Entries entries;
  for (std::uint64_t i = 0; i < 300; ++i) {
    entries.emplace_back("${V}", i + 1);
  }

  GlobFixture fixture;
  ASSERT_OK(fixture.init(std::move(entries)));
  fixture.bind(1, "x", 1);
  const auto matches = fixture.lookup("x");
  ASSERT_EQ(matches.size(), 300U);
  for (std::size_t i = 0; i < matches.size(); ++i) {
    ASSERT_EQ(matches[i], i + 1);
  }
}

TEST(GlobMap, RejectsMalformedAndUnrepresentablePatterns) {
  GlobFixture fixture;
  assertErrorContains(
      fixture.init({{std::string(BPFJ_GLOB_MAP_MAX_TOKENS + 1, 'a'), 1}}),
      "too long");
  assertErrorContains(fixture.init({{"${V", 1}}), "Unterminated");
  assertErrorContains(fixture.init({{"${V}", 1}}, {}), "none are bound");
  assertErrorContains(
      fixture.init(
          {{"${V}", 1}},
          [](std::string_view) -> bpfjailer::err::Expected<__u32> {
            return 0;
          }),
      "reserved key 0");

  Entries tooManyWords;
  for (std::size_t i = 0; i <= BPFJ_GLOB_MAP_MAX_WORDS; ++i) {
    tooManyWords.emplace_back(numberedPattern(i), i);
  }
  assertErrorContains(
      fixture.init(std::move(tooManyWords)), "Too many glob patterns");

  Entries tooManyAccepts;
  for (std::size_t i = 0; i <= BPFJ_GLOB_MAP_MAX_ACCEPTS; ++i) {
    tooManyAccepts.emplace_back("", i);
  }
  assertErrorContains(
      fixture.init(std::move(tooManyAccepts)), "Too many glob patterns");

  Entries tooManyVars;
  for (std::size_t i = 0; i <= BPFJ_GLOB_MAP_MAX_BINDINGS; ++i) {
    tooManyVars.emplace_back("${V" + std::to_string(i) + "}", i);
  }
  assertErrorContains(
      fixture.init(
          std::move(tooManyVars),
          [](std::string_view name) -> bpfjailer::err::Expected<__u32> {
            return static_cast<__u32>(
                std::stoul(std::string(name.substr(1))) + 1);
          }),
      "Too many distinct glob variables");
}
