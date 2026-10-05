import React, { lazy } from 'react';
import { ViewGridOutline } from 'mdi-material-ui';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import type { DefenseArea } from '../defenseAreas';

const defenseMatrix: DefenseArea = {
  order: 20,
  path: 'matrix',
  label: 'Defense matrix',
  description: 'Which techniques of the threats you face can you see, detect and prove you detect?',
  icon: <ViewGridOutline fontSize="small" />,
  needs: [KNOWLEDGE],
  sections: [
    { path: 'coverage', label: 'Matrix' },
    { path: 'gaps', label: 'Gaps' },
  ],
  component: lazy(() => import('../matrix/Root')),
};

export default defenseMatrix;
