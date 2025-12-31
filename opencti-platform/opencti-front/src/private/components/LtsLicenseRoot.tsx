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

import React, { FunctionComponent, useState } from 'react';
import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { StyledEngineProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import makeStyles from '@mui/styles/makeStyles';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Alert from '@mui/material/Alert';
import FormGroup from '@mui/material/FormGroup';
import TextField from '@mui/material/TextField';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import { LtsLicenseRootQuery, LtsLicenseRootQuery$data } from '@components/__generated__/LtsLicenseRootQuery.graphql';
import { ConnectedThemeProvider } from '../../components/AppThemeProvider';
import { ConnectedIntlProvider } from '../../components/AppIntlProvider';
import { environment, handleError } from '../../relay/environment';
import SystemBanners from '../../public/components/SystemBanners';
import type { Theme } from '../../components/Theme';
import { useFormatter } from '../../components/i18n';
import useApiMutation from '../../utils/hooks/useApiMutation';
import Message from '../../components/Message';
import { isEmptyField } from '../../utils/utils';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    textAlign: 'center',
    margin: '0 auto',
    width: '80%',
    paddingBottom: 50,
  },
}));

export const licenseQuery = graphql`
  query LtsLicenseRootQuery {
    settings {
      id
      platform_enterprise_edition {
        license_by_configuration
      }
      ...AppThemeProvider_settings
      ...AppIntlProvider_settings
    }
  }
`;

const LicenseRootMutationFieldPatch = graphql`
  mutation LtsLicenseRootMutation($input: LicenseActivationInput!) {
      setupEnterpriseLicense(input: $input) {
          id
      }
  }
`;

const queryRef = loadQuery<LtsLicenseRootQuery>(
  environment,
  licenseQuery,
  {},
);

interface LicenseProps {
  settings: LtsLicenseRootQuery$data['settings'];
}

const LicenseComponent: FunctionComponent<LicenseProps> = ({ settings }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [enterpriseLicense, setEnterpriseLicense] = useState('');
  const [commitMutation] = useApiMutation(LicenseRootMutationFieldPatch);
  const enableEnterpriseEdition = () => {
    commitMutation({
      variables: {
        input: {
          settingId: settings.id,
          license: enterpriseLicense,
        },
      },
      onError: (error: Error) => {
        handleError(error);
      },
      onCompleted: () => {
        window.location.reload();
      },
    });
  };
  const isNoLicenseByConfig = !settings.platform_enterprise_edition.license_by_configuration;
  return (
    <div>
      <SystemBanners settings={settings} />
      <div className={classes.container}>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={true}
          onClose={() => {}}
          fullWidth={true}
          maxWidth="md"
        >
          <DialogTitle>
            {t_i18n('OpenCTI LTS license agreement')}
          </DialogTitle>
          <DialogContent>
            <Alert severity="info" style={{ marginTop: 15 }}>
              {t_i18n('OpenCTI LTS Edition requires a license key to be enabled. Filigran provides a free-to-use license for development and research purposes as well as for charity organizations.')}
              <br /><br />
              {t_i18n('To obtain a license, please')} <a href="https://filigran.io/contact/" target="_blank" rel="noreferrer">{t_i18n('reach out to the Filigran team')}</a>.
            </Alert>
            {isNoLicenseByConfig ? (
              <FormGroup style={{ marginTop: 15 }}>
                <TextField
                  onChange={(event) => setEnterpriseLicense(event.target.value)}
                  multiline={true}
                  fullWidth={true}
                  minRows={10}
                  placeholder={t_i18n('Paste your Filigran OpenCTI LTS license')}
                  variant="outlined"
                />
              </FormGroup>
            ) : (
              <Alert severity="warning" style={{ marginTop: 15 }}>
                {t_i18n('The license you setup in configuration is invalid, please change it or remove it to allow direct configuration in this screen')}
              </Alert>
            )}
            {isNoLicenseByConfig && (
              <div style={{ marginTop: 15 }}>
                {t_i18n('By enabling the OpenCTI LTS, you (and your organization) agrees to the')}&nbsp;
                <a href="https://github.com/OpenCTI-Platform/opencti/blob/master/LTS_LICENSE" target="_blank" rel="noreferrer">{t_i18n('license terms and conditions of usage')}</a>.
              </div>
            )}
          </DialogContent>
          {isNoLicenseByConfig && (
            <DialogActions>
              <Button disabled={isEmptyField(enterpriseLicense)} color="secondary" onClick={enableEnterpriseEdition}>
                {t_i18n('Enable')}
              </Button>
            </DialogActions>
          )}
        </Dialog>
      </div>
    </div>
  );
};

const LtsLicenseRoot = () => {
  const { settings } = usePreloadedQuery<LtsLicenseRootQuery>(
    licenseQuery,
    queryRef,
  );

  return (
    <StyledEngineProvider injectFirst={true}>
      <ConnectedThemeProvider settings={settings}>
        <CssBaseline />
        <ConnectedIntlProvider settings={settings}>
          <Message />
          <LicenseComponent settings={settings} />
        </ConnectedIntlProvider>
      </ConnectedThemeProvider>
    </StyledEngineProvider>
  );
};

export default LtsLicenseRoot;
