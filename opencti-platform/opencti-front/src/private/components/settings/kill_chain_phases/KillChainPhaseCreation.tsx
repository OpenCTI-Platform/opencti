import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { insertNode } from '../../../../utils/store';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { PaginationOptions } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';

const killChainPhaseMutation = graphql`
  mutation KillChainPhaseCreationMutation($input: KillChainPhaseAddInput!) {
    killChainPhaseAdd(input: $input) {
      ...KillChainPhasesLine_node
    }
  }
`;

const CreateKillChainPhaseControlledDial = (
  props: DrawerControlledDialProps,
) => (
  <CreateEntityControlledDial
    entityType="Kill-Chain-Phase"
    {...props}
  />
);
interface KillChainPhaseCreationProps {
  paginationOptions: PaginationOptions;
}
const KillChainPhaseCreation: FunctionComponent<
  KillChainPhaseCreationProps
> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const killChainPhaseValidation = Yup.object().shape({
    kill_chain_name: Yup.string().required(t_i18n('This field is required')),
    phase_name: Yup.string().required(t_i18n('This field is required')),
  });
  const initialValues = {
    kill_chain_name: '',
    phase_name: '',
    x_opencti_order: '',
  };
  const onSubmit = (
    values: typeof initialValues,
    { setSubmitting, resetForm }: {
      setSubmitting: (flag: boolean) => void;
      resetForm: () => void;
    },
  ) => {
    const finalValues = {
      ...values,
      x_opencti_order: parseInt(values.x_opencti_order, 10),
    };
    commitMutation({
      ...defaultCommitMutation,
      mutation: killChainPhaseMutation,
      variables: { input: finalValues },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_killChainPhases',
          paginationOptions,
          'killChainPhaseAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };
  return (
    <Drawer
      title={t_i18n('Create a kill chain phase')}
      controlledDial={CreateKillChainPhaseControlledDial}
    >
      {({ onClose }) => (
        <Formik
          initialValues={initialValues}
          validationSchema={killChainPhaseValidation}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="kill_chain_name"
                label={t_i18n('Kill chain name')}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="phase_name"
                label={t_i18n('Phase name')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="x_opencti_order"
                label={t_i18n('Order')}
                fullWidth={true}
                type="number"
                style={{ marginTop: 20 }}
              />
              <div style={{
                marginTop: 20,
                textAlign: 'right',
              }}
              >
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  style={{ marginLeft: theme.spacing(2) }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
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
export default KillChainPhaseCreation;
