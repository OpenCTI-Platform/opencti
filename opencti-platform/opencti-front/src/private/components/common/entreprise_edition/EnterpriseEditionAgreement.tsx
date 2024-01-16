import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React, { FunctionComponent, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { now } from '../../../../utils/Time';

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
  const [enterpriseEditionConsent, setEnterpriseEditionConsent] = useState(false);
  const [commitMutation] = useMutation(
    EnterpriseEditionAgreementMutationFieldPatch,
  );
  const enableEnterpriseEdition = () => {
    commitMutation({
      variables: {
        id: settingsId,
        input: {
          key: 'enterprise_edition',
          value: now(),
        },
      },
    });
    onClose();
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
          {t_i18n(
            'By enabling the OpenCTI Enterprise Edition, you (and your organization) agrees to the OpenCTI Enterprise Edition (EE) supplemental license terms and conditions of usage:',
          )}
        </span>
        <ul>
          <li>
            {t_i18n(
              'OpenCTI EE is free-to-use for development, testing and research purposes as well as for non-profit organizations.',
            )}
          </li>
          <li>
            {t_i18n(
              'OpenCTI EE is included for all Filigran SaaS customers without additional fee.',
            )}
          </li>
          <li>
            {t_i18n(
              'For all other usages, you (and your organization) should have entered in a',
            )}{' '}
            <a href="https://filigran.io/offering/subscribe" target="_blank" rel="noreferrer">
              {t_i18n('Filigran Enterprise agreement')}
            </a>
            .
          </li>
        </ul>
        <FormGroup>
          <FormControlLabel
            control={
              <Checkbox
                checked={enterpriseEditionConsent}
                onChange={(event) => setEnterpriseEditionConsent(event.target.checked)
                }
              />
            }
            label={
              <>
                <span>{t_i18n('I have read and agree to the')}</span>{' '}
                <a
                  href="https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE"
                  target="_blank" rel="noreferrer"
                >
                  {t_i18n('OpenCTI EE license terms')}
                </a>
                .
              </>
            }
          />
        </FormGroup>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button
          color="secondary"
          onClick={enableEnterpriseEdition}
          disabled={!enterpriseEditionConsent}
        >
          {t_i18n('Enable')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EnterpriseEditionAgreement;
