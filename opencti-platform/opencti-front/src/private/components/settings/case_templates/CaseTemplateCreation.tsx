import Button from '@common/button/Button';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { Field, Form, Formik } from 'formik';
import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';
import CaseTemplateTasks from '../../common/form/CaseTemplateTasks';
import { CaseTemplateLinesPaginationQuery$variables } from './__generated__/CaseTemplateLinesPaginationQuery.graphql';

const caseTemplateMutation = graphql`
  mutation CaseTemplateCreationMutation($input: CaseTemplateAddInput!) {
    caseTemplateAdd(input: $input) {
      ...CaseTemplateLine_node
    }
  }
`;

const CreateCaseTemplateControlledDial = (
  props: DrawerControlledDialProps,
) => (
  <CreateEntityControlledDial
    entityType="Case-Template"
    {...props}
  />
);

interface CaseTemplateCreationProps {
  paginationOptions?: CaseTemplateLinesPaginationQuery$variables;
}

const CaseTemplateCreation: FunctionComponent<CaseTemplateCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const caseTemplateValidation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    tasks: Yup.array(),
  });
  const initialValues = {
    name: '',
    description: '',
    tasks: [],
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
      tasks: values.tasks.map(({ value }) => value),
    };
    setSubmitting(true);
    commitMutation({
      ...defaultCommitMutation,
      mutation: caseTemplateMutation,
      variables: { input: finalValues },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_caseTemplates',
          paginationOptions,
          'caseTemplateAdd',
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
      title={t_i18n('Create a case template')}
      controlledDial={CreateCaseTemplateControlledDial}
    >
      {({ onClose }) => (
        <Formik
          initialValues={initialValues}
          validationSchema={caseTemplateValidation}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
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
                rows="4"
                style={{ marginTop: 20 }}
              />
              <CaseTemplateTasks
                onChange={setFieldValue}
                values={values.tasks}
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

export default CaseTemplateCreation;
