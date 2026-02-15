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
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import { useFormatter } from '../../../../components/i18n';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import Card from '@common/card/Card';

const EnterpriseEdition = ({ title, message, feature }: { title?: string; message?: string; feature?: string }) => {
  const { isSensitive, isAllowed } = useSensitiveModifications('ce_ee_toggle');
  const { t_i18n } = useFormatter();
  return (
    <>
      <Card title={title ? t_i18n(title) : ''}>
        {t_i18n(message ?? 'You need to activate OpenCTI enterprise edition to use this feature.')}
        <EnterpriseEditionButton disabled={!isAllowed && isSensitive} feature={feature} />
      </Card>
    </>
  );
};

export default EnterpriseEdition;
