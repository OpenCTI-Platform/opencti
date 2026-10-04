import { lazy } from 'react';
import type { CurationTab } from '../curationTabs';

const inbox: CurationTab = {
  order: 10,
  path: 'inbox',
  label: 'Inbox',
  component: lazy(() => import('../CurationInbox')),
};

export default inbox;
