import { attackPatternCaseSensitiveDuplicatedId, attackPatternCaseSensitiveDuplicatedIdDryRun } from './operations/attackPatternCaseSensitiveDuplicatedId';

import type { SanityOperation } from './dataSanity-types';

const SANITY_OPERATIONS: SanityOperation[] = [
  {
    name: 'attackPatternCaseSensitiveDuplicatedId',
    dryRun: attackPatternCaseSensitiveDuplicatedIdDryRun,
    operationRun: attackPatternCaseSensitiveDuplicatedId,
    execution_type: 'run_once',
  },
];

export const sanityOperationList = () => {
  return SANITY_OPERATIONS;
};
