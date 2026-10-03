import React, { lazy, Suspense } from 'react';
import type { EntityChangesSectionProps } from '@components/common/changes/entityChangesSections';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const MergeRecords = lazy(() => import('./MergeRecords'));

/** The Merges section of an entity's Changes tab: its merges, each one reversible (Unmerge) from the record drawer. */
const EntityMergesSection = ({ entityId }: EntityChangesSectionProps) => (
  <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
    <MergeRecords entityId={entityId} />
  </Suspense>
);

export default EntityMergesSection;
