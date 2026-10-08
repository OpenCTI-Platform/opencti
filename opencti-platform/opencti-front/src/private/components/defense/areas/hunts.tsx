import React, { lazy } from 'react';
import { Crosshairs } from 'mdi-material-ui';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import type { DefenseArea } from '../defenseAreas';

const hunts: DefenseArea = {
  order: 10,
  path: 'hunts',
  label: 'Hunts',
  icon: <Crosshairs fontSize="small" />,
  entityType: 'Hunt',
  needs: [KNOWLEDGE],
  // A hunt's own page (`/dashboard/defense/hunts/<id>/...`) has its header, breadcrumb and tabs.
  rendersOwnPage: (subPath) => subPath.length > 0,
  component: lazy(() => import('../../hunts/RootHunts')),
};

export default hunts;
