import React, { lazy, Suspense } from 'react';
import type { EntityChangesSectionProps } from '@components/common/changes/entityChangesSections';
import CurationSkeleton from './CurationSkeleton';

const MergeRecords = lazy(() => import('./MergeRecords'));

/** The Merges section of an entity's Changes tab: its merges, each one reversible (Undo the merge) from the record drawer. */
const EntityMergesSection = ({ entityId }: EntityChangesSectionProps) => (
  <Suspense fallback={<CurationSkeleton blocks={[48, 240]} />}>
    <MergeRecords entityId={entityId} />
  </Suspense>
);

export default EntityMergesSection;
