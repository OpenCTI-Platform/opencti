import React, { lazy } from 'react';
import { ShieldSyncOutline } from 'mdi-material-ui';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import type { DefenseArea } from '../defenseAreas';

const disseminationAssurance: DefenseArea = {
  order: 30,
  path: 'assurance',
  label: 'Dissemination assurance',
  icon: <ShieldSyncOutline fontSize="small" />,
  needs: [KNOWLEDGE],
  component: lazy(() => import('@components/data/dissemination_assurance/Root')),
};

export default disseminationAssurance;
