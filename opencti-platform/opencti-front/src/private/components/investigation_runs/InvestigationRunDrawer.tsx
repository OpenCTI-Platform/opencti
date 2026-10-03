/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { Suspense } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import InvestigationRunView from './InvestigationRunView';

interface InvestigationRunDrawerProps {
  runId: string | null;
  currentEntityId?: string;
  onClose: () => void;
}

/** A live investigation of an entity that has no Autopilot tab (incidents, indicators, observables). */
const InvestigationRunDrawer = ({ runId, currentEntityId, onClose }: InvestigationRunDrawerProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Drawer title={t_i18n('Case Autopilot')} open={!!runId} onClose={onClose}>
      {runId ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <InvestigationRunView runId={runId} currentEntityId={currentEntityId} onDeleted={onClose} />
        </Suspense>
      ) : null}
    </Drawer>
  );
};

export default InvestigationRunDrawer;
