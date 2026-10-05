import { lazy } from 'react';
import { KNOWLEDGE } from '../../../../../utils/hooks/useGranted';
import type { CurationTab } from '../curationTabs';
import useCurationPendingCount from '../useCurationPendingCount';

const inbox: CurationTab = {
  order: 10,
  path: 'inbox',
  label: 'Inbox',
  needs: [KNOWLEDGE],
  useBadgeCount: useCurationPendingCount,
  component: lazy(() => import('../CurationInbox')),
};

export default inbox;
