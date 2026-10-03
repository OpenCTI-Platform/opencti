import { lazy } from 'react';
import type { CurationTab } from '../curationTabs';

const conflicts: CurationTab = {
  order: 20,
  path: 'conflicts',
  label: 'Conflicts',
  component: lazy(() => import('../../provenance/SourceConflicts')),
};

export default conflicts;
