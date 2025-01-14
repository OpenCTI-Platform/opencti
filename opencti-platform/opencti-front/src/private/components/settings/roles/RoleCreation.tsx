import React from 'react';
import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import { Button, useTheme } from '@mui/material';
import * as Yup from 'yup';
import { ConnectionHandler, graphql } from 'react-relay';
import { DataID, RecordProxy, RecordSourceSelectorProxy } from 'relay-runtime';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { PaginationOptions } from '../../../../components/list_lines';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

const roleMutation = graphql`
  mutation RoleCreationMutation($input: RoleAddInput!) {
    roleAdd(input: $input) {
      ...RoleLine_node
    }
  }
`;

type FormValuesType = {
  name: string,
  description: string,
};

const CreateRoleControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType='Role'
    entityPrefix={false}
    size='medium'
    {...props}
  />
);

const RoleCreation = ({ paginationOptions }: {
  paginationOptions: PaginationOptions
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const roleValidation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });

  const sharedUpdater = (
    store: RecordSourceSelectorProxy,
    userId: DataID,
    newEdge: RecordProxy,
  ) => {
    const userProxy = store.get(userId);
    if (!userProxy) return;

    const conn = ConnectionHandler.getConnection(
      userProxy,
      'Pagination_roles',
      paginationOptions,
    );
    if (!conn) return;

    ConnectionHandler.insertEdgeBefore(conn, newEdge);
  };

  const onSubmit = (
    values: FormValuesType,
    { setSubmitting, resetForm }: {
      setSubmitting: (flag: boolean) => void,
      resetForm: () => void,
    },
  ) => {
    commitMutation({
      ...defaultCommitMutation,
      mutation: roleMutation,
      variables: {
        input: values,
      },
      updater: (store: RecordSourceSelectorProxy) => {
        const payload = store.getRootField('roleAdd');
        if (!payload) return;

        const newEdge = payload.setLinkedRecord(payload, 'node');
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          newEdge,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  const initialValues: FormValuesType = {
    name: '',
    description: '',
  };

  return (
    <Drawer
      title={t_i18n('Create a role')}
      variant={isFABReplaced ? undefined : DrawerVariant.createWithPanel}
      controlledDial={isFABReplaced ? CreateRoleControlledDial : undefined}
    >
      {({ onClose }) => (
        <Formik
          initialValues={initialValues}
          validationSchema={roleValidation}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, isValid }) => (
            <Form>
              <Field
                component={TextField}
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
                fullWidth={true}
                multiline={true}
                rows={4}
                style={{ marginTop: 20 }}
              />
              <div style={{
                marginTop: 20,
                textAlign: 'right',
              }}
              >
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  style={{ marginLeft: theme.spacing(2) }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting || !isValid}
                  style={{ marginLeft: theme.spacing(2) }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default RoleCreation;
