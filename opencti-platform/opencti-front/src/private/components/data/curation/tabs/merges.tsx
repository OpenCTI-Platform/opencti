import { lazy } from 'react';
import type { CurationTab } from '../curationTabs';

const merges: CurationTab = {
  order: 40,
  path: 'merges',
  label: 'Merges',
  component: lazy(() => import('../CurationMerges')),
};

export default merges;
