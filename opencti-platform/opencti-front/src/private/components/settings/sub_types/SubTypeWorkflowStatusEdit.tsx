import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import StatusTemplateField from '../../common/form/StatusTemplateField';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { SubTypeWorkflowStatusEdit_subType$key } from './__generated__/SubTypeWorkflowStatusEdit_subType.graphql';
import { SubTypeWorkflowStatusEditQuery } from './__generated__/SubTypeWorkflowStatusEditQuery.graphql';
import { StatusForm, statusValidation } from './statusFormUtils';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const statusEditFieldPatchMutation = graphql`
  mutation SubTypeWorkflowStatusEditFieldPatchMutation(
    $id: ID!
    $statusId: String!
    $input: [EditInput]!
  ) {
    subTypeEdit(id: $id) {
      statusFieldPatch(statusId: $statusId, input: $input) {
        ...SubTypeWorkflow_subType
      }
    }
  }
`;

export const statusEditQuery = graphql`
  query SubTypeWorkflowStatusEditQuery($id: String!) {
    status(id: $id) {
      ...SubTypeWorkflowStatusEdit_subType
    }
  }
`;

export const statusEditFragment = graphql`
  fragment SubTypeWorkflowStatusEdit_subType on Status {
    id
    order
    scope
    template {
      id
      name
      color
    }
  }
`;

type StatusEditForm = StatusForm & { order: NonNullable<StatusForm['order']> };

interface StatusEditionProps {
  subTypeId: string;
  handleClose: () => void;
  open: boolean;
  queryRef: PreloadedQuery<SubTypeWorkflowStatusEditQuery>;
}

const SubTypeWorkflowStatusEdit: FunctionComponent<StatusEditionProps> = ({
  subTypeId,
  handleClose,
  open,
  queryRef,
}) => {
  const data = usePreloadedFragment<
    SubTypeWorkflowStatusEditQuery,
    SubTypeWorkflowStatusEdit_subType$key
  >({
    queryDef: statusEditQuery,
    fragmentDef: statusEditFragment,
    queryRef,
    nodePath: 'status',
  });
  const { t_i18n } = useFormatter();

  const initialValues: StatusEditForm = {
    template: data.template
      ? {
          label: data.template.name,
          value: data.template.id,
          color: data.template.color,

        }
      : null,
    order: String(data.order) || '',
  };

  const [commit] = useApiMutation(statusEditFieldPatchMutation);
  const handleSubmitStatusTemplate: FormikConfig<StatusEditForm>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const input = [
      { key: 'template_id', value: values.template?.value || '' },
      { key: 'order', value: values.order },
    ];

    commit({
      variables: {
        id: subTypeId,
        statusId: data.id,
        input,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };
  return (
    <Formik
      initialValues={initialValues}
      validationSchema={statusValidation(t_i18n)}
      onSubmit={handleSubmitStatusTemplate}
    >
      {({ submitForm, isSubmitting, setFieldValue }) => (
        <Form>
          <Dialog
            open={open}
            slotProps={{ paper: { elevation: 1 } }}
            onClose={submitForm}
            fullWidth={true}
            slots={{ transition: Transition }}
          >
            <DialogTitle>{t_i18n('Update a status')}</DialogTitle>
            <DialogContent>
              <StatusTemplateField
                name="template"
                setFieldValue={setFieldValue}
                helpertext=""
              />
              <Field
                component={TextField}
                variant="standard"
                name="order"
                label={t_i18n('Order')}
                fullWidth={true}
                type="number"
                style={{ marginTop: 20 }}
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

export default SubTypeWorkflowStatusEdit;
