import { lazy } from 'react';
import { KNOWLEDGE } from '../../../../../utils/hooks/useGranted';
import type { CurationTab } from '../curationTabs';

const merges: CurationTab = {
  order: 40,
  path: 'merges',
  label: 'Merges',
  needs: [KNOWLEDGE],
  component: lazy(() => import('../CurationMerges')),
};

export default merges;
