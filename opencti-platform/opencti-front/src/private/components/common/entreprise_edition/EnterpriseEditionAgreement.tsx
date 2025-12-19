import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import FormGroup from '@mui/material/FormGroup';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import TextField from '@mui/material/TextField';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { isEmptyField } from '../../../../utils/utils';

const EnterpriseEditionAgreementMutationFieldPatch = graphql`
  mutation EnterpriseEditionAgreementMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        ...RootSettings
      }
    }
  }
`;

interface EnterpriseEditionAgreementProps {
  open: boolean;
  onClose: () => void;
  settingsId: string;
}

const EnterpriseEditionAgreement: FunctionComponent<
  EnterpriseEditionAgreementProps
> = ({ open, onClose, settingsId }) => {
  const { t_i18n } = useFormatter();
  const [enterpriseLicense, setEnterpriseLicense] = useState('');
  const [commitMutation] = useApiMutation(
    EnterpriseEditionAgreementMutationFieldPatch,
  );
  const enableEnterpriseEdition = () => {
    commitMutation({
      variables: {
        id: settingsId,
        input: [{
          key: 'enterprise_license',
          value: enterpriseLicense,
        }],
      },
      onCompleted: () => {
        onClose();
      },
    });
  };
  return (
    <Dialog
      slotProps={{ paper: { elevation: 1 } }}
      open={open}
      onClose={onClose}
      fullWidth={true}
      maxWidth="md"
    >
      <DialogTitle>
        {t_i18n('OpenCTI Enterprise Edition (EE) license agreement')}
      </DialogTitle>
      <DialogContent>
        <Alert severity="info" style={{ marginTop: 15 }}>
          {t_i18n('OpenCTI Enterprise Edition requires a license key to be enabled. Filigran provides a free-to-use license for development and research purposes as well as for charity organizations.')}
          <br /><br />
          {t_i18n('To obtain a license, please')} <a href="https://filigran.io/contact/" target="_blank" rel="noreferrer">{t_i18n('reach out to the Filigran team')}</a>.
          <br />
          {t_i18n('You just need to try?')} Get right now <a href="https://filigran.io/enterprise-editions-trial/" target="_blank" rel="noreferrer">{t_i18n('your trial license online')}</a>.
        </Alert>
        <FormGroup style={{ marginTop: 15 }}>
          <TextField
            onChange={(event) => setEnterpriseLicense(event.target.value)}
            multiline={true}
            fullWidth={true}
            minRows={10}
            placeholder={t_i18n('Paste your Filigran OpenCTI Enterprise Edition license')}
            variant="outlined"
          />
        </FormGroup>
        <div style={{ marginTop: 15 }}>
          {t_i18n('By enabling the OpenCTI Enterprise Edition, you (and your organization) agrees to the OpenCTI Enterprise Edition (EE) ')}
          <a href="https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE" target="_blank" rel="noreferrer">{t_i18n('license terms and conditions of usage')}</a>.
        </div>
      </DialogContent>
      <DialogActions>
        <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button
          onClick={enableEnterpriseEdition}
          disabled={isEmptyField((enterpriseLicense))}
        >
          {t_i18n('Enable')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EnterpriseEditionAgreement;
