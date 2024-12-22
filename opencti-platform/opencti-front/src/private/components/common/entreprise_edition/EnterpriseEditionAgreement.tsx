import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import FormGroup from '@mui/material/FormGroup';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
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
      PaperProps={{ elevation: 1 }}
      open={open}
      onClose={onClose}
      fullWidth={true}
      maxWidth="md"
    >
      <DialogTitle>
        {t_i18n('OpenCTI Enterprise Edition (EE) license agreement')}
      </DialogTitle>
      <DialogContent>
        <span>
          {t_i18n('By enabling the OpenCTI Enterprise Edition, you (and your organization) agrees to the OpenCTI Enterprise Edition (EE) supplemental ')}
          <a href="https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE" target="_blank" rel="noreferrer">{t_i18n('license terms and conditions of usage')}</a>
        </span>
        <Alert severity="error" style={{ marginTop: 16 }}>
          {t_i18n('OpenCTI EE required an annual subscription. However the license will be granted for free to development, testing and research purposes and charity organizations with NGO status.')}
          <br/><br/>
          <b>
            {t_i18n(' Please contact Filigran to get your license at ')}
            <a href="mailto:sales@filigran.io" target="_blank" rel="noreferrer">
              sales@filigran.io
            </a>
          </b>
        </Alert>
        <Alert severity="info" style={{ marginTop: 16 }}>
          {t_i18n('If you simply want to try the OpenCTI Enterprise edition, get your license at ')}
          <a href="https://filigran.io/ee-trial" target="_blank" rel="noreferrer">
            {'https://filigran.io/ee-trial'}
          </a>
        </Alert>
        <FormGroup style={{ marginTop: 16 }}>
          <TextField
            onChange={(event) => setEnterpriseLicense(event.target.value)}
            multiline={true}
            fullWidth={true}
            minRows={20}
            placeholder={t_i18n('Paste your Filigran license')}
            variant="outlined"
          />
        </FormGroup>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button
          color="secondary"
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
