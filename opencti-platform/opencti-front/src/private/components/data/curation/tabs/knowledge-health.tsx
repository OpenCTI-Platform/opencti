import { lazy } from 'react';
import { KNOWLEDGE } from '../../../../../utils/hooks/useGranted';
import type { CurationTab } from '../curationTabs';

const knowledgeHealth: CurationTab = {
  order: 50,
  path: 'health',
  label: 'Knowledge health',
  needs: [KNOWLEDGE],
  component: lazy(() => import('../CurationKnowledgeHealth')),
};

export default knowledgeHealth;
