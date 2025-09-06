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
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '@components/Error';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import Pirs from './Pirs';
import Pir from './Pir';
import Loader from '../../../components/Loader';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import { useFormatter } from '../../../components/i18n';

const PirRoot = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  return (
    <Suspense fallback={<Loader />}>
      {isEnterpriseEdition
        ? <Routes>
          <Route path="/" element={boundaryWrapper(Pirs)}/>
          <Route path="/:pirId/*" element={boundaryWrapper(Pir)}/>
        </Routes>
        : <EnterpriseEdition feature={t_i18n('PIR')} />}
    </Suspense>
  );
};

export default PirRoot;
