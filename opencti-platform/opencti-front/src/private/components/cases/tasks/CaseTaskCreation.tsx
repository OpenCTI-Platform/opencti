import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql, useMutation } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import TextField from '../../../../components/TextField';
import { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { Option } from '../../common/form/ReferenceField';
import { CaseTasksLinesQuery$variables } from './__generated__/CaseTasksLinesQuery.graphql';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const caseTaskAddMutation = graphql`
  mutation CaseTaskCreationMutation($input: TaskAddInput!) {
    taskAdd(input: $input) {
      ...CaseTasksLine_data
    }
  }
`;

interface FormikCaseTaskAddInput {
  name: string;
  due_date?: Date | null;
  description?: string;
  objectAssignee?: Option[];
  objectParticipant: Option[];
  objectLabel?: Option[];
  objectMarking: Option[];
}

interface CaseTaskCreationProps {
  caseId: string;
  onClose: () => void;
  paginationOptions: CaseTasksLinesQuery$variables;
  defaultMarkings?: { value: string; label: string }[];
}

const CaseTaskCreation: FunctionComponent<CaseTaskCreationProps> = ({
  caseId,
  onClose,
  paginationOptions,
  defaultMarkings,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable().max(5000, t('The value is too long')),
    due_date: Yup.date().nullable(),
    objectLabel: Yup.array(),
    objectMarking: Yup.array(),
    objectAssignee: Yup.array(),
    objectParticipant: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const taskValidator = useSchemaEditionValidation('Task', basicShape);

  const [addTask] = useMutation(caseTaskAddMutation);

  const onSubmit: FormikConfig<FormikCaseTaskAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    setSubmitting(true);

    addTask({
      variables: {
        input: {
          ...values,
          objectAssignee: (values.objectAssignee ?? []).map(
            ({ value }) => value,
          ),
          objectParticipant: values.objectParticipant.map(({ value }) => value),
          objectLabel: (values.objectLabel ?? []).map(({ value }) => value),
          objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
          objects: [caseId],
        },
      },
      updater: (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_tasks', paginationOptions, 'taskAdd'),
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        onClose();
      },
    });
  };
  return (
    <Formik<FormikCaseTaskAddInput>
      initialValues={{
        name: '',
        description: '',
        due_date: null,
        objectAssignee: [],
        objectParticipant: [],
        objectMarking: defaultMarkings ?? [],
      }}
      onSubmit={onSubmit}
      onReset={onClose}
      validationSchema={taskValidator}
    >
      {({ isSubmitting, handleReset, submitForm }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            style={{ marginBottom: 20 }}
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth
          />
          <Field
            component={DateTimePickerField}
            name="due_date"
            TextFieldProps={{
              label: t('Due Date'),
              variant: 'standard',
              fullWidth: true,
            }}
          />
          <ObjectAssigneeField
            name="objectAssignee"
            style={fieldSpacingContainerStyle}
          />
          <ObjectParticipantField
            name="objectParticipant"
            style={fieldSpacingContainerStyle}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
            fullWidth
            multiline
            rows="4"
            style={fieldSpacingContainerStyle}
          />
          <div className={classes.buttons}>
            <Button
              onClick={handleReset}
              disabled={isSubmitting}
              variant="contained"
              classes={{ root: classes.button }}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default CaseTaskCreation;
