import { lazy } from 'react';
import type { CurationTab } from '../curationTabs';
import { useConflictsCount } from '../../provenance/provenanceCurationCounts';
import { KNOWLEDGE } from '../../../../../utils/hooks/useGranted';

const conflicts: CurationTab = {
  order: 20,
  path: 'conflicts',
  label: 'Conflicts',
  needs: [KNOWLEDGE],
  isAvailable: (modules) => modules.isProvenanceEnabled(),
  useBadgeCount: useConflictsCount,
  component: lazy(() => import('../../provenance/SourceConflicts')),
};

export default conflicts;
