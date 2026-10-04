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
  component: lazy(() => import('../../hunts/RootHunts')),
};

export default hunts;
