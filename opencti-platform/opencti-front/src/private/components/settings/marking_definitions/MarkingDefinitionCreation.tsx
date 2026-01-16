import Button from '@common/button/Button';
import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import ColorPickerField from '../../../../components/ColorPickerField';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';
import { PaginationOptions } from '../../../../components/list_lines';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';

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
    {...props}
  />
);

interface MarkingDefinitionCreationProps {
  paginationOptions: PaginationOptions;
}

const MarkingDefinitionCreation: FunctionComponent<
  MarkingDefinitionCreationProps
> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

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
      controlledDial={CreateMarkingDefinitionControlledDial}
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
              <FormButtonContainer>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </FormButtonContainer>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default MarkingDefinitionCreation;
