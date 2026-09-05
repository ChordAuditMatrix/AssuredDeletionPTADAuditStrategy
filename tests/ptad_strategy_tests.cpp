/* SPDX-License-Identifier: GPL-3.0-or-later */
/** @file ptad_strategy_tests.cpp @brief PTAD overwrite and trace smoke test. */

#include "AssuredDeletionPTADAuditStrategy/strategy.h"

#include <cstdlib>

int main() {
  using Strategy =
      CAMatrix::Audit::Strategies::AssuredDeletionPTADAuditStrategy;
  Strategy strategy;
  const auto deleted =
      Strategy::overwriteWithPattern({{1, 2, 3, 4}}, {1}, {9, 8});
  const auto receipt = Strategy::makeReceipt("file", {1}, 7, {9, 8});
  return strategy.algorithmType() == "AssuredDeletionPTAD" &&
                 deleted[0] != std::vector<std::uint8_t>({1, 2, 3, 4}) &&
                 receipt.traceValue != 0
             ? EXIT_SUCCESS
             : EXIT_FAILURE;
}
