import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import { insertNode } from '../../../../utils/store';
import CaseTemplateTasks from '../../common/form/CaseTemplateTasks';
import { CaseTemplateAddInput } from './__generated__/CaseTemplateCreationMutation.graphql';
import { CaseTemplateLinesPaginationQuery$variables } from './__generated__/CaseTemplateLinesPaginationQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useSchemaCreationValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const caseTemplateMutation = graphql`
  mutation CaseTemplateCreationMutation($input: CaseTemplateAddInput!) {
    caseTemplateAdd(input: $input) {
      ...CaseTemplateLine_node
    }
  }
`;

const OBJECT_TYPE = 'Case-Template';

interface CaseTemplateCreationProps {
  paginationOptions?: CaseTemplateLinesPaginationQuery$variables;
}

const CaseTemplateCreation: FunctionComponent<CaseTemplateCreationProps> = ({
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const basicShape: Yup.ObjectShape = {
    name: Yup.string(),
    description: Yup.string().nullable(),
    tasks: Yup.array(),
  };
  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const validator = useSchemaCreationValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const [commitMutation] = useApiMutation(caseTemplateMutation);

  const onSubmit: FormikConfig<CaseTemplateAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const input = { ...values, tasks: values.tasks.map(({ value }) => value) };
    setSubmitting(true);
    commitMutation({
      variables: { input },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_caseTemplates',
          paginationOptions,
          'caseTemplateAdd',
        );
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
    <Drawer
      title={t_i18n('Create a case template')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <Formik<CaseTemplateAddInput>
          initialValues={{
            name: '',
            description: '',
            tasks: [],
          }}
          validationSchema={validator}
          onSubmit={(values, formikHelpers) => {
            onSubmit(values, formikHelpers);
            onClose();
          }}
          onReset={onClose}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setFieldValue,
            values,
          }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                required={(mandatoryAttributes.includes('name'))}
                fullWidth={true}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
                required={(mandatoryAttributes.includes('description'))}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
              />
              <CaseTemplateTasks
                onChange={setFieldValue}
                values={values.tasks}
              />
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
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

export default CaseTemplateCreation;
