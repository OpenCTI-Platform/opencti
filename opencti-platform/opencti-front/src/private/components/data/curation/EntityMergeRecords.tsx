import React from 'react';
import type { EntityChangesViewProps } from '@components/common/changes/entityChangesViews';
import MergeRecords from './MergeRecords';

/** The Merges view of an entity's Changes tab: its merges, each one reversible (Unmerge) from the record drawer. */
const EntityMergeRecords = ({ entityId }: EntityChangesViewProps) => <MergeRecords entityId={entityId} />;

export default EntityMergeRecords;
