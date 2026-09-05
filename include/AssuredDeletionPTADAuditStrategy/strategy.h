/* SPDX-License-Identifier: GPL-3.0-or-later */
/** @file strategy.h @brief PTAD assured-deletion audit strategy. */
#ifndef CAMATRIX_ASSURED_DELETION_PTAD_STRATEGY_H
#define CAMATRIX_ASSURED_DELETION_PTAD_STRATEGY_H

#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/request_result.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Strategies {

/**
 * CoreLib adaptation of PTAD's unlink-overwrite-verify pipeline.
 *
 * The authenticated PDP pipeline is supplied by the native SM9 aggregate
 * scheme.  PTAD-specific code supplies deterministic pattern overwrite and a
 * serialisable deletion receipt.  Distributed blockchain anchoring remains an
 * integration concern outside a hot-loadable audit plugin.
 */
class AssuredDeletionPTADAuditStrategy final
    : public CAMatrix::Audit::Core::DynamicAuditStrategy {
public:
  std::string algorithmType() const override { return "AssuredDeletionPTAD"; }
  std::string version() const override { return "2.0.0"; }

  CAMatrix::Audit::Messages::Capabilities caps() const override;
  CAMatrix::Audit::Core::StateMaintenanceParty
  stateMaintenanceParty() const override;
  std::shared_ptr<CAMatrix::Audit::Core::DynamicPdpStateStore>
  createStateStore(CAMatrix::Audit::Core::BlockMetadataFactory metadataFactory)
      const override;
  void
  setAlgorithm(CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm) override;
  CAMatrix::Audit::Messages::InitializeAlgorithmResult initializeAlgorithm(
      const CAMatrix::Audit::Messages::InitializeAlgorithmRequest &) override;
  CAMatrix::Audit::Messages::GenerateKeysResult
  generateKeys(const CAMatrix::Audit::Messages::GenerateKeysRequest &) override;
  CAMatrix::Audit::Messages::GenerateTagsResult
  generateTags(const CAMatrix::Audit::Messages::GenerateTagsRequest &) override;
  CAMatrix::Audit::Messages::MaintainResult
  maintenance(const CAMatrix::Audit::Messages::MaintainRequest &) override;
  CAMatrix::Audit::Messages::GenerateChallengesResult generateChallenges(
      const CAMatrix::Audit::Messages::GenerateChallengesRequest &) override;
  CAMatrix::Audit::Messages::GenerateProofsResult generateProofs(
      const CAMatrix::Audit::Messages::GenerateProofsRequest &) override;
  CAMatrix::Audit::Messages::VerifyProofsResult
  verifyProofs(const CAMatrix::Audit::Messages::VerifyProofsRequest &) override;
  CAMatrix::Audit::Messages::AuditRequestVariantPtr
  createRequest(CAMatrix::Audit::Core::AuditOperation,
                const CAMatrix::Audit::Core::AuditOperationContext &,
                const CAMatrix::Audit::Messages::RawInput & = {}) override;

  struct DeletionReceipt {
    std::string objectId;
    std::vector<std::size_t> overwrittenBlocks;
    std::uint64_t epoch{0};
    std::uint64_t traceValue{0};
  };

  /** Implements PTAD's overwrite phase; each chosen block is replaced by
   * a pattern derived from the deletion nonce and its physical position. */
  static std::vector<std::vector<std::uint8_t>>
  overwriteWithPattern(const std::vector<std::vector<std::uint8_t>> &blocks,
                       const std::vector<std::size_t> &oneBasedIndices,
                       const std::vector<std::uint8_t> &deletionNonce);

  /** In-place counterpart used when the storage owner applies a deletion. */
  static void
  overwriteWithPatternInPlace(std::vector<std::vector<std::uint8_t>> &blocks,
                              const std::vector<std::size_t> &oneBasedIndices,
                              const std::vector<std::uint8_t> &deletionNonce);

  /** Builds the compact, appendable trace record for the deletion event. */
  static DeletionReceipt
  makeReceipt(std::string objectId, std::vector<std::size_t> overwrittenBlocks,
              std::uint64_t epoch,
              const std::vector<std::uint8_t> &deletionNonce);

protected:
  const CAMatrix::Audit::Core::AuditStrategyArtifactFactory &
  artifactFactory() const override;

private:
  CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm_;
};
} // namespace CAMatrix::Audit::Strategies

namespace CAMatrix::Audit::Core {
extern "C" AuditStrategy *create_audit_strategy() noexcept;
extern "C" void destroy_audit_strategy(AuditStrategy *strategy) noexcept;
} // namespace CAMatrix::Audit::Core
#endif
