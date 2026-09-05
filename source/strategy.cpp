/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Native PTAD unlink -> overwrite -> challenge/response lifecycle. */
#include "AssuredDeletionPTADAuditStrategy/strategy.h"
#include "ChordAuditMatrixLib/interfaces/audit/artifact_factory.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/in_memory_tags.h"
#include "DHTDynamicAuditStrategy/state_stores/dynamic_hash_table_state_store.h"
#include <algorithm>
#include <json/json.h>
#include <map>
#include <numeric>
#include <random>
#include <stdexcept>
#include <utility>

namespace CAMatrix::Audit::Strategies {
namespace {
using namespace CAMatrix::Audit::Core;
using namespace CAMatrix::Audit::Messages;
constexpr std::uint64_t p = 1000000007ULL, q = 1000000009ULL, N = p * q,
                        g = 49ULL;
std::uint64_t mulmod(std::uint64_t a, std::uint64_t b) {
  return static_cast<std::uint64_t>((static_cast<__uint128_t>(a) * b) % N);
}
std::uint64_t powmod(std::uint64_t b, std::uint64_t e) {
  std::uint64_t out = 1;
  for (; e; e >>= 1, b = mulmod(b, b))
    if (e & 1)
      out = mulmod(out, b);
  return out;
}
std::uint64_t hash64(const std::string &s) {
  std::uint64_t h = 1469598103934665603ULL;
  for (auto c : s)
    h = (h ^ static_cast<unsigned char>(c)) * 1099511628211ULL;
  return h % N;
}
class ScalarTag final : public Tag {
public:
  std::uint64_t value = 1;
  ScalarTag() = default;
  explicit ScalarTag(std::uint64_t v) : value(v) {}
  void assign(const Tag &x) override {
    value = dynamic_cast<const ScalarTag &>(x).value;
  }
  std::shared_ptr<Tag> operator+(const Tag &x) const override {
    return std::make_shared<ScalarTag>(
        mulmod(value, dynamic_cast<const ScalarTag &>(x).value));
  }
  bool operator==(const Tag &x) const override {
    return value == dynamic_cast<const ScalarTag &>(x).value;
  }

protected:
  void do_serialize(cereal::BinaryOutputArchive &ar) const override {
    ar(value);
  }
  void do_deserialize(cereal::BinaryInputArchive &ar) override { ar(value); }
};
class PTADChallenges final : public Challenges {
public:
  std::vector<std::size_t> selected;
  std::uint64_t key = 0;

protected:
  void do_serialize(cereal::BinaryOutputArchive &ar) const override {
    ar(selected, key);
  }
  void do_deserialize(cereal::BinaryInputArchive &ar) override {
    ar(selected, key);
  }
};
class PTADProof final : public Proves {
public:
  std::uint64_t complement = 1;

protected:
  void do_serialize(cereal::BinaryOutputArchive &ar) const override {
    ar(complement);
  }
  void do_deserialize(cereal::BinaryInputArchive &ar) override {
    ar(complement);
  }
};
class PTADParams final : public AlgoPublicParams {
protected:
  void do_serialize(cereal::BinaryOutputArchive &) const override {}
  void do_deserialize(cereal::BinaryInputArchive &) override {}
};
struct TagsExt final : StageExtBase {
  std::string fid;
};
struct MaintExt final : StageExtBase {
  std::string fid;
  std::vector<std::size_t> indices;
  std::uint64_t seed = 0;
};
struct ChallengeExt final : StageExtBase {
  std::string fid;
  std::size_t count = 0;
  std::uint64_t seed = 0;
};
struct ProofExt final : StageExtBase {
  bool replay = false;
};
struct File {
  std::vector<std::uint64_t> m, tags, preTags;
  std::uint64_t total = 1, seed = 0;
  std::vector<std::size_t> deleted;
};
std::map<std::string, File> files;
std::string active;
std::vector<std::size_t> readIndices(const Json::Value &r) {
  const auto &x = r.isMember("targetBlockIndices") ? r["targetBlockIndices"]
                                                   : r["blockIndices"];
  std::vector<std::size_t> v;
  if (x.isArray())
    for (const auto &i : x) {
      auto n = static_cast<std::size_t>(i.asUInt64());
      v.push_back(n == 0 ? 1 : n);
    }
  return v;
}
std::uint64_t tag(std::string const &fid, std::size_t i, std::uint64_t m) {
  return mulmod(hash64(fid + ":" + std::to_string(i)), powmod(g, m));
}
class Factory final : public AuditStrategyArtifactFactory {
public:
  AuditArtifactVariant createArtifact(AuditArtifactKind k) const override {
    if (k == AuditArtifactKind::AlgorithmPublicParams ||
        k == AuditArtifactKind::UserPublicParams)
      return std::static_pointer_cast<AlgoPublicParams>(
          std::make_shared<PTADParams>());
    if (k == AuditArtifactKind::Tag)
      return std::static_pointer_cast<Tag>(std::make_shared<ScalarTag>());
    if (k == AuditArtifactKind::Challenges)
      return std::static_pointer_cast<Challenges>(
          std::make_shared<PTADChallenges>());
    if (k == AuditArtifactKind::Proves)
      return std::static_pointer_cast<Proves>(std::make_shared<PTADProof>());
    throw std::runtime_error("PTAD artifact unavailable");
  }
};
} // namespace
Capabilities AssuredDeletionPTADAuditStrategy::caps() const {
  return Capabilities::DynamicUpdate;
}
StateMaintenanceParty
AssuredDeletionPTADAuditStrategy::stateMaintenanceParty() const {
  return StateMaintenanceParty::Public;
}
std::shared_ptr<DynamicPdpStateStore>
AssuredDeletionPTADAuditStrategy::createStateStore(BlockMetadataFactory) const {
  return std::make_shared<DHTDynamic::DynamicHashTableStateStore>();
}
void AssuredDeletionPTADAuditStrategy::setAlgorithm(
    CAMatrix::Crypto::CryptoGeneralAlgorithmPtr x) {
  algorithm_ = std::move(x);
}
const AuditStrategyArtifactFactory &
AssuredDeletionPTADAuditStrategy::artifactFactory() const {
  static Factory f;
  return f;
}
InitializeAlgorithmResult AssuredDeletionPTADAuditStrategy::initializeAlgorithm(
    const InitializeAlgorithmRequest &) {
  InitializeAlgorithmResult r;
  r.ok = true;
  r.publicParams = std::make_shared<PTADParams>();
  return r;
}
GenerateKeysResult
AssuredDeletionPTADAuditStrategy::generateKeys(const GenerateKeysRequest &) {
  GenerateKeysResult r;
  r.ok = true;
  r.publicParams = std::make_shared<PTADParams>();
  return r;
}
GenerateTagsResult
AssuredDeletionPTADAuditStrategy::generateTags(const GenerateTagsRequest &in) {
  GenerateTagsResult r;
  auto e = std::dynamic_pointer_cast<TagsExt>(in.ext);
  if (!e || !in.blocks)
    return r;
  auto out = std::make_shared<InMemoryTags>(
      [] { return std::make_shared<ScalarTag>(); });
  File f;
  for (std::size_t o = 0; o < in.blocks->availableBlockCount(); ++o) {
    auto m = hash64(
        std::string(reinterpret_cast<const char *>(in.blocks->block(o).data()),
                    in.blocks->block(o).size()));
    f.m.push_back(m);
    auto t = tag(e->fid, o + 1, m);
    f.tags.push_back(t);
    f.total = mulmod(f.total, t);
    out->set(o, std::make_shared<ScalarTag>(t));
  }
  files[e->fid] = f;
  active = e->fid;
  r.tags = out;
  r.ext = e;
  return r;
}
MaintainResult
AssuredDeletionPTADAuditStrategy::maintenance(const MaintainRequest &in) {
  MaintainResult r;
  auto e = std::dynamic_pointer_cast<MaintExt>(in.ext);
  auto it = files.find(e ? e->fid : "");
  if (!e || in.type != MaintenanceOpType::Delete || it == files.end())
    return r;
  auto &f = it->second;
  if (e->indices.empty()) {
    e->indices.resize(f.m.size());
    for (std::size_t i = 0; i < f.m.size(); ++i)
      e->indices[i] = i + 1;
  }
  f.preTags = f.tags;
  f.seed = e->seed;
  auto out = std::make_shared<InMemoryTags>(
      [] { return std::make_shared<ScalarTag>(); });
  f.total = 1;
  for (auto i : e->indices) {
    if (!i || i > f.m.size())
      throw std::out_of_range("PTAD deletion index");
    f.m[i - 1] = hash64("PTAD:seed:" + std::to_string(e->seed) + ":" +
                        std::to_string(i));
    f.deleted.push_back(i);
  }
  for (std::size_t o = 0; o < f.m.size(); ++o) {
    f.tags[o] = tag(e->fid, o + 1, f.m[o]);
    f.total = mulmod(f.total, f.tags[o]);
    out->set(o, std::make_shared<ScalarTag>(f.tags[o]));
  }
  active = e->fid;
  r.tags = out;
  r.ext = e;
  return r;
}
GenerateChallengesResult AssuredDeletionPTADAuditStrategy::generateChallenges(
    const GenerateChallengesRequest &in) {
  GenerateChallengesResult r;
  auto e = std::dynamic_pointer_cast<ChallengeExt>(in.ext);
  auto it = files.find(e ? e->fid : "");
  if (!e || it == files.end() || it->second.deleted.empty())
    return r;
  std::vector<std::size_t> v(it->second.m.size());
  std::iota(v.begin(), v.end(), 1);
  std::mt19937_64 gen(e->seed);
  std::shuffle(v.begin(), v.end(), gen);
  v.resize(std::min(v.size(), e->count ? e->count : v.size()));
  auto c = std::make_shared<PTADChallenges>();
  c->selected = std::move(v);
  c->key = e->seed;
  r.challenges = c;
  r.ext = e;
  return r;
}
GenerateProofsResult AssuredDeletionPTADAuditStrategy::generateProofs(
    const GenerateProofsRequest &in) {
  GenerateProofsResult r;
  auto c = std::dynamic_pointer_cast<PTADChallenges>(in.challenges);
  auto e = std::dynamic_pointer_cast<ProofExt>(in.ext);
  auto it = files.find(active);
  if (!c || it == files.end())
    return r;
  std::vector<bool> selected(it->second.m.size());
  for (auto i : c->selected)
    selected[i - 1] = true;
  auto proof = std::make_shared<PTADProof>();
  for (std::size_t o = 0; o < selected.size(); ++o)
    if (!selected[o]) {
      const auto stale =
          e && e->replay &&
          std::find(it->second.deleted.begin(), it->second.deleted.end(),
                    o + 1) != it->second.deleted.end();
      proof->complement =
          mulmod(proof->complement,
                 stale ? it->second.preTags[o] : it->second.tags[o]);
    }
  r.proves = proof;
  return r;
}
VerifyProofsResult
AssuredDeletionPTADAuditStrategy::verifyProofs(const VerifyProofsRequest &in) {
  VerifyProofsResult r;
  if (in.challenges.empty() || in.proves.empty())
    return r;
  auto c = std::dynamic_pointer_cast<PTADChallenges>(in.challenges.front());
  auto p0 = std::dynamic_pointer_cast<PTADProof>(in.proves.front());
  auto it = files.find(active);
  if (!c || !p0 || it == files.end())
    return r;
  std::uint64_t selected = 1;
  for (auto i : c->selected) {
    if (!i || i > it->second.m.size())
      return r;
    const auto deleted =
        std::find(it->second.deleted.begin(), it->second.deleted.end(), i) !=
        it->second.deleted.end();
    const auto value =
        deleted ? hash64("PTAD:seed:" + std::to_string(it->second.seed) + ":" +
                         std::to_string(i))
                : it->second.m[i - 1];
    selected = mulmod(selected, tag(active, i, value));
  }
  r.ok = mulmod(selected, p0->complement) == it->second.total;
  r.reason = r.ok ? "" : "PTAD total-tag equation rejected";
  return r;
}
AuditRequestVariantPtr AssuredDeletionPTADAuditStrategy::createRequest(
    AuditOperation op, const AuditOperationContext &ctx, const RawInput &in) {
  switch (op) {
  case AuditOperation::AlgorithmInit: {
    auto r = std::make_shared<InitializeAlgorithmRequest>();
    r->ext = std::make_shared<StageExtBase>();
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::KeyGeneration: {
    auto r = std::make_shared<GenerateKeysRequest>();
    r->ext = std::make_shared<StageExtBase>();
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::GenerateTags: {
    auto r = std::make_shared<GenerateTagsRequest>();
    auto e = std::make_shared<TagsExt>();
    auto d = in.requireCustom<AuditDataMap>(op);
    r->blocks = d->getRequired<
        std::shared_ptr<CAMatrix::Audit::Data::AuditBlockSource>>("blocks");
    e->fid = d->getRequired<std::string>("fileId");
    r->ext = e;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::Maintenance: {
    auto x = in.requireJson(op);
    auto r = std::make_shared<MaintainRequest>();
    r->type = MaintenanceOpType::Delete;
    r->tags = ctx.generateTagsResult->tags;
    auto e = std::make_shared<MaintExt>();
    e->fid = x.get("fileId", active).asString();
    e->indices = readIndices(x);
    e->seed = x.get("seed", 42).asUInt64();
    r->ext = e;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::ChallengeGen: {
    auto x = in.requireJson(op);
    auto r = std::make_shared<GenerateChallengesRequest>();
    auto e = std::make_shared<ChallengeExt>();
    e->fid = x.get("fileId", active).asString();
    e->count = x.get("challengeCount", 0).asUInt64();
    e->seed = x.get("seed", 42).asUInt64();
    r->ext = e;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::ProofGen: {
    auto r = std::make_shared<GenerateProofsRequest>();
    r->challenges = ctx.generateChallengesResult->challenges;
    auto d = in.requireCustom<AuditDataMap>(op);
    auto e = std::make_shared<ProofExt>();
    e->replay = d->getOptional<bool>("adversarialReplay").value_or(false);
    r->ext = e;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::ProofVerify: {
    auto r = std::make_shared<VerifyProofsRequest>();
    r->challenges = {ctx.generateChallengesResult->challenges};
    r->proves = {ctx.generateProofsResult->proves};
    r->ext = std::make_shared<StageExtBase>();
    return std::make_shared<AuditRequestVariant>(r);
  }
  }
  throw std::runtime_error("unsupported PTAD operation");
}
std::vector<std::vector<std::uint8_t>>
AssuredDeletionPTADAuditStrategy::overwriteWithPattern(
    const std::vector<std::vector<std::uint8_t>> &b,
    const std::vector<std::size_t> &i, const std::vector<std::uint8_t> &n) {
  auto r = b;
  overwriteWithPatternInPlace(r, i, n);
  return r;
}
void AssuredDeletionPTADAuditStrategy::overwriteWithPatternInPlace(
    std::vector<std::vector<std::uint8_t>> &b,
    const std::vector<std::size_t> &i, const std::vector<std::uint8_t> &n) {
  if (n.empty())
    throw std::invalid_argument("PTAD deletion nonce");
  for (auto x : i) {
    if (!x || x > b.size())
      throw std::out_of_range("PTAD target");
    for (std::size_t j = 0; j < b[x - 1].size(); ++j)
      b[x - 1][j] = n[(x + j) % n.size()];
  }
}
AssuredDeletionPTADAuditStrategy::DeletionReceipt
AssuredDeletionPTADAuditStrategy::makeReceipt(
    std::string id, std::vector<std::size_t> i, std::uint64_t e,
    const std::vector<std::uint8_t> &n) {
  return {std::move(id), std::move(i), e,
          hash64(std::string(n.begin(), n.end()))};
}
} // namespace CAMatrix::Audit::Strategies
namespace CAMatrix::Audit::Core {
extern "C" AuditStrategy *create_audit_strategy() noexcept {
  return new CAMatrix::Audit::Strategies::AssuredDeletionPTADAuditStrategy();
}
extern "C" void destroy_audit_strategy(AuditStrategy *s) noexcept { delete s; }
} // namespace CAMatrix::Audit::Core
