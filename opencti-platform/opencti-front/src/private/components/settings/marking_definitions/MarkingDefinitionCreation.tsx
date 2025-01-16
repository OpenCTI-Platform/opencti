import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import { Button } from '@mui/material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '../../common/drawer/Drawer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import ColorPickerField from '../../../../components/ColorPickerField';
import { insertNode } from '../../../../utils/store';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { PaginationOptions } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';

const markingDefinitionMutation = graphql`
  mutation MarkingDefinitionCreationMutation(
    $input: MarkingDefinitionAddInput!
  ) {
    markingDefinitionAdd(input: $input) {
      ...MarkingDefinitionsLine_node
    }
  }
`;

const CreateMarkingDefinitionControlledDial = (
  props: DrawerControlledDialProps,
) => (
  <CreateEntityControlledDial
    entityType="Marking-Definition"
    size="medium"
    {...props}
  />
);

interface MarkingDefinitionCreationProps {
  paginationOptions: PaginationOptions,
}

const MarkingDefinitionCreation: FunctionComponent<
MarkingDefinitionCreationProps
> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const markingDefinitionValidation = Yup.object().shape({
    definition_type: Yup.string().required(t_i18n('This field is required')),
    definition: Yup.string().required(t_i18n('This field is required')),
    x_opencti_color: Yup.string().required(t_i18n('This field is required')),
    x_opencti_order: Yup.number()
      .typeError(t_i18n('The value must be a number'))
      .integer(t_i18n('The value must be a number'))
      .required(t_i18n('This field is required')),
  });

  const initialValues = {
    definition_type: '',
    definition: '',
    x_opencti_color: '',
    x_opencti_order: '',
  };

  const onSubmit = (
    values: typeof initialValues,
    { setSubmitting, resetForm }: {
      setSubmitting: (flag: boolean) => void,
      resetForm: () => void,
    },
  ) => {
    const finalValues = {
      ...values,
      x_opencti_order: parseInt(values.x_opencti_order, 10),
    };
    commitMutation({
      ...defaultCommitMutation,
      mutation: markingDefinitionMutation,
      variables: { input: finalValues },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_markingDefinitions',
          paginationOptions,
          'markingDefinitionAdd',
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
      title={t_i18n('Create a marking definition')}
      variant={isFABReplaced ? undefined : DrawerVariant.createWithPanel}
      controlledDial={isFABReplaced
        ? CreateMarkingDefinitionControlledDial
        : undefined
      }
    >
      {({ onClose }) => (
        <Formik
          initialValues={initialValues}
          validationSchema={markingDefinitionValidation}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="definition_type"
                label={t_i18n('Type')}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="definition"
                label={t_i18n('Definition')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <Field
                component={ColorPickerField}
                name="x_opencti_color"
                label={t_i18n('Color')}
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

export default MarkingDefinitionCreation;
