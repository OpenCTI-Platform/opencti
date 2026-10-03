import { lazy } from 'react';
import type { CurationTab } from '../curationTabs';

const knowledgeHealth: CurationTab = {
  order: 50,
  path: 'health',
  label: 'Knowledge health',
  component: lazy(() => import('../CurationKnowledgeHealth')),
};

export default knowledgeHealth;
