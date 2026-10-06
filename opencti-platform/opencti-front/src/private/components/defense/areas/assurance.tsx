import React, { lazy } from 'react';
import { ShieldSyncOutline } from 'mdi-material-ui';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import { DISSEMINATION_ASSURANCE_SECTIONS } from '../../data/dissemination_assurance/disseminationAssuranceUtils';
import type { DefenseArea } from '../defenseAreas';

const disseminationAssurance: DefenseArea = {
  order: 30,
  path: 'assurance',
  label: 'Dissemination assurance',
  description: 'Do the indicators you share reach your security platforms, and do they still work there?',
  icon: <ShieldSyncOutline fontSize="small" />,
  needs: [KNOWLEDGE],
  sections: [...DISSEMINATION_ASSURANCE_SECTIONS],
  component: lazy(() => import('@components/data/dissemination_assurance/Root')),
};

export default disseminationAssurance;
