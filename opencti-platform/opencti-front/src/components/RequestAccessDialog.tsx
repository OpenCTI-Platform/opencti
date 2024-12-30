import React from 'react';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import ObjectOrganizationField from '@components/common/form/ObjectOrganizationField';
import { Field, Form } from 'formik';
import { graphql } from 'react-relay';
import MarkdownField from './fields/MarkdownField';
import { useFormatter } from './i18n';
import Transition from './Transition';

const requestAccessDialogMutation = graphql`
  mutation RequestAccessDialogMutation($input: RequestAccessAddInput!) {
    requestAccessAdd(input: $input)
  }
`;

interface RequestAccessDialogProps {
  open: boolean;
  onClose: () => void;
}

const RequestAccessDialog: React.FC<RequestAccessDialogProps> = ({ open, onClose }) => {
  const { t_i18n } = useFormatter();
  const submitRequestAccess = () => {
    return console.log('SubmittedRequestAccess ! ');
  };
  return (
    <Dialog
      open={open}
      PaperProps={{ variant: 'elevation', elevation: 1 }}
      keepMounted={true}
      fullWidth={true}
      TransitionComponent={Transition}
      onClose={onClose}
    >
      <DialogContent>
        <DialogTitle style={{ padding: '16px 0' }}>{t_i18n('Request Access for entity')}</DialogTitle>
        <DialogContentText>
          {t_i18n('Your account/organization does not have permission to create/update this entity as it already exist in the platform but is under restriction. You can make an access request from the original entity owner below. This will notify the organization that created the entity that you wish to access it.')}
        </DialogContentText>
        <Form>
          <Field
            component={MarkdownField}
            name="justification"
            label={t_i18n('Enter justification for requesting this entity')}
            fullWidth={true}
            multiline={true}
            style={{ marginTop: 20 }}
            askAi={false}
          />
          <ObjectOrganizationField
            name="objectOrganization"
            style={{ width: '100%', paddingTop: '16px' }}
            label={t_i18n('Organization')}
            multiple={false}
            alert={false}
          />
        </Form>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>
          {t_i18n('Cancel')}
        </Button>
        <Button color="secondary" onClick={submitRequestAccess}>
          {t_i18n('Request Access')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default RequestAccessDialog;
