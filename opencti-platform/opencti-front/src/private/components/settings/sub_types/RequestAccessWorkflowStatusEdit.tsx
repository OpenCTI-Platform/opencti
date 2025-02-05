import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import StatusTemplateField from '@components/common/form/StatusTemplateField';
import Button from '@mui/material/Button';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import { Option } from '@components/common/form/ReferenceField';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { RequestAccessWorkflowStatusEditQuery } from './__generated__/RequestAccessWorkflowStatusEditQuery.graphql';

export const requestAccessWorkflowStatusEditQuery = graphql`
  query RequestAccessWorkflowStatusEditQuery($id: String!) {
    entitySetting(id: $id) {
      ...RequestAccessWorkflowStatusEdit_status
    }
  }
`;

const requestAccessWorkflowStatusEditFragment = graphql`
  fragment RequestAccessWorkflowStatusEdit_status on EntitySetting {
    id
    requestAccessStatus {
      name
      color
      id
    }
  }
`;

interface RequestAccessWorkflowStatusFormProps {
  entitySettingId: string;
  onSubmit: () => void;
  open: boolean;
  queryRef: PreloadedQuery<RequestAccessWorkflowStatusEditQuery>
}

export interface WorkflowStatusEditFormData {
  template: Option;
}

const RequestAccessWorkflowStatusForm: FunctionComponent<RequestAccessWorkflowStatusFormProps> = ({
  entitySettingId,
  onSubmit,
  open,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedFragment({
    queryDef: requestAccessWorkflowStatusEditQuery,
    fragmentDef: requestAccessWorkflowStatusEditFragment,
    queryRef,
    nodePath: 'entitySetting',
  });

  const status = data.requestAccessStatus;
  const initialValues = {
    template: {
      label: status?.[0]?.name || '',
      color: status?.[0]?.color || '',
      value: status?.[0]?.id || '',
    },
  };

  return (
    <Formik<WorkflowStatusEditFormData>
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting, setFieldValue }) => (
        <Form>
          <Dialog
            open={open}
            PaperProps={{ elevation: 1 }}
            onClose={submitForm}
            fullWidth={true}
            TransitionComponent={Transition}
          >
            <DialogTitle>{t_i18n('Update a status')}</DialogTitle>
            <DialogContent>
              <StatusTemplateField
                name="template"
                setFieldValue={setFieldValue}
                helpertext={''}
              />
              <DialogActions>
                <Button onClick={submitForm} disabled={isSubmitting}>
                  {t_i18n('Close')}
                </Button>
              </DialogActions>
            </DialogContent>
          </Dialog>
        </Form>
      )}
    </Formik>
  );
};

export default RequestAccessWorkflowStatusForm;
