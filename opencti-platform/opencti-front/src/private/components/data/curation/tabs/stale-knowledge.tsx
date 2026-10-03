import { lazy } from 'react';
import type { CurationTab } from '../curationTabs';

const staleKnowledge: CurationTab = {
  order: 30,
  path: 'stale-knowledge',
  label: 'Stale knowledge',
  component: lazy(() => import('../../provenance/StaleKnowledge')),
};

export default staleKnowledge;
