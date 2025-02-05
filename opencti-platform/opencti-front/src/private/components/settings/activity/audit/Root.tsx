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

import React from 'react';
import Audit from './Audit';
import EnterpriseEdition from '../../../common/entreprise_edition/EnterpriseEdition';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import { useFormatter } from '../../../../../components/i18n';
import Security from '../../../../../utils/Security';
import { SETTINGS_SECURITYACTIVITY } from '../../../../../utils/hooks/useGranted';

const Root = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();

  if (!isEnterpriseEdition) {
    return <EnterpriseEdition feature={t_i18n('Activity')} />;
  }
  return (
    <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<span>{t_i18n(
      'You do not have any access to the audit activity of this OpenCTI instance.',
    )}</span>}
    >
      <Audit />
    </Security>

  );
};

export default Root;
