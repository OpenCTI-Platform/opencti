/*
Copyright (c) 2021-2024 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import React from 'react';
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import type { Theme } from '../../../../components/Theme';

const EnterpriseEdition = ({ message, feature }: { message?: string, feature?: string }) => {
  const theme = useTheme<Theme>();

  const { isSensitiveModificationEnabled, isAllowed } = useSensitiveModifications();

  const { t_i18n } = useFormatter();
  return (
    <>
      <Alert
        icon={false}
        severity="warning"
        variant="outlined"
        style={{
          position: 'relative',
          width: '100%',
          marginBottom: 20,
          borderColor: isSensitiveModificationEnabled ? theme.palette.dangerZone.main : theme.palette.ee.main,
          color: theme.palette.text?.primary,
        }}
      >
        <AlertTitle style={{ marginBottom: 0, fontWeight: 400 }}>
          {t_i18n(message ?? 'You need to activate OpenCTI enterprise edition to use this feature.')}
          <EnterpriseEditionButton disabled={!isAllowed} feature={feature} />
        </AlertTitle>
      </Alert>
    </>
  );
};

export default EnterpriseEdition;
