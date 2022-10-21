import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import { pick, pipe, assoc } from 'ramda';
import * as Yup from 'yup';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import MenuItem from '@mui/material/MenuItem';
import * as R from 'ramda';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { statusCreationStatusTemplatesQuery } from './StatusCreation';
import SelectField from '../../../../components/SelectField';

const statusMutationFieldPatch = graphql`
  mutation StatusEditionFieldPatchMutation(
    $id: ID!
    $statusId: String!
    $input: [EditInput]!
  ) {
    subTypeEdit(id: $id) {
      statusFieldPatch(statusId: $statusId, input: $input) {
        ...SubTypeEdition_subType
      }
    }
  }
`;

const statusValidation = (t) => Yup.object().shape({
  template_id: Yup.string().required(t('This field is required')),
  order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

export const StatusEditionFragment = graphql`
    fragment StatusEdition_status on Status {
        id
        order
        template {
            id
            name
            color
        }
    }
`;

const StatusEdition = ({ subTypeId, handleClose, open, status }) => {
  const { t } = useFormatter();

  const data = useFragment(StatusEditionFragment, status);

  const initialValues = pipe(
    assoc('template_id', data.template.id),
    pick(['template_id', 'order']),
  )(data);

  const handleSubmitField = (name, value) => {
    statusValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: statusMutationFieldPatch,
          variables: {
            id: subTypeId,
            statusId: data.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={statusValidation(t)}
    >
      {() => (
        <Form>
          <Dialog
            open={open}
            PaperProps={{ elevation: 1 }}
            onClose={handleClose}
            fullWidth={true}
          >
            <DialogTitle>{t('Create a status')}</DialogTitle>
            <DialogContent>
              <QueryRenderer
                query={statusCreationStatusTemplatesQuery}
                render={({ props }) => {
                  if (props && props.statusTemplates) {
                    const statusTemplatesEdges = props.statusTemplates.edges;
                    const statusTemplates = R.map(
                      (n) => n.node,
                      statusTemplatesEdges,
                    );
                    return (
                      <Field
                        component={SelectField}
                        variant="standard"
                        name="template_id"
                        onChange={handleSubmitField}
                        label={t('Name')}
                        fullWidth={true}
                        containerstyle={{ width: '100%' }}
                      >
                        {statusTemplates.map((statusTemplate) => (
                          <MenuItem
                            key={statusTemplate.id}
                            value={statusTemplate.id}
                          >
                            {statusTemplate.name}
                          </MenuItem>
                        ))}
                      </Field>
                    );
                  }
                  return <div />;
                }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="order"
                label={t('Order')}
                fullWidth={true}
                type="number"
                style={{ marginTop: 20 }}
              />
              <DialogActions>
                <Button onClick={handleClose}>{t('Close')}</Button>
              </DialogActions>
            </DialogContent>
          </Dialog>
        </Form>
      )}
    </Formik>
  );
};

export default StatusEdition;
