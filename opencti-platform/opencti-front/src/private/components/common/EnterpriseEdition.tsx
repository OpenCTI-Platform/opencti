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

import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import AlertTitle from '@mui/material/AlertTitle';
import { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';

const useStyles = makeStyles<Theme>(() => ({
  alert: {
    width: '100%',
    marginBottom: 20,
  },
}));

const EnterpriseEdition = () => {
  const classes = useStyles();
  const { t } = useFormatter();
  return (
    <Alert
      icon={false}
      classes={{ root: classes.alert, message: classes.message }}
      severity="warning"
      variant="outlined"
      style={{ position: 'relative' }}
    >
      <AlertTitle style={{ marginBottom: 0 }}>
        {t(
          'You need to activate OpenCTI enterprise edition to use this feature.',
        )}
        <br />
      </AlertTitle>
    </Alert>
  );
};

export default EnterpriseEdition;
