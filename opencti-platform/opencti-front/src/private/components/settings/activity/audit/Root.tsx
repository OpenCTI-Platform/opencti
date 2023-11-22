/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import Audit from './Audit';
import EnterpriseEdition from '../../../common/entreprise_edition/EnterpriseEdition';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import { useFormatter } from '../../../../../components/i18n';

const Root = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t } = useFormatter();

  if (!isEnterpriseEdition) {
    return <EnterpriseEdition feature={t('Activity')} />;
  }
  return <Audit />;
};

export default Root;
