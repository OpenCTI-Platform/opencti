import { lazy } from 'react';
import type { CurationTab } from '../curationTabs';
import { useConflictsCount } from '../../provenance/provenanceCurationCounts';

const conflicts: CurationTab = {
  order: 20,
  path: 'conflicts',
  label: 'Conflicts',
  isAvailable: (modules) => modules.isProvenanceEnabled(),
  useBadgeCount: useConflictsCount,
  component: lazy(() => import('../../provenance/SourceConflicts')),
};

export default conflicts;
