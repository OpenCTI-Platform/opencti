import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql, useMutation } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import TextField from '../../../../components/TextField';
import { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { Option } from '../../common/form/ReferenceField';
import { TaskCreationMutation, TaskCreationMutation$variables } from './__generated__/TaskCreationMutation.graphql';
import { TasksLinesPaginationQuery$variables } from './__generated__/TasksLinesPaginationQuery.graphql';
import { insertNode } from '../../../../utils/store';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const taskAddMutation = graphql`
  mutation TaskCreationMutation($input: TaskAddInput!) {
    taskAdd(input: $input) {
      ...TasksLine_node
      ... on Task {
        objects {
          edges {
            node {
              ...Tasks_tasks
            }
          }
        }
      }
    }
  }
`;

interface FormikTaskAddInput {
  name: string
  due_date?: Date | null
  description?: string
  objectAssignee?: Option[]
  objectLabel?: Option[]
  objectMarking: Option[]
}

interface TaskCreationProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
  ) => void;
  onClose?: () => void;
  defaultMarkings?: { value: string, label: string }[]
}

const TaskCreationForm: FunctionComponent<TaskCreationProps> = ({
  updater,
  onClose,
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
    x_opencti_workflow_id: Yup.object(),
  };
  const taskValidator = useSchemaEditionValidation('Task', basicShape);

  const [commit] = useMutation<TaskCreationMutation>(taskAddMutation);

  const initialValues: FormikTaskAddInput = {
    name: '',
    description: '',
    due_date: null,
    objectAssignee: [],
    objectMarking: defaultMarkings ?? [],
  };

  const onSubmit: FormikConfig<FormikTaskAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    const input: TaskCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      due_date: values.due_date,
      objectAssignee: (values.objectAssignee ?? []).map(({ value }) => value),
      objectLabel: (values.objectLabel ?? []).map(({ value }) => value),
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
    };
    commit({
      variables: {
        input,
      },
      updater: (store: RecordSourceSelectorProxy) => {
        if (updater) {
          updater(store, 'taskAdd');
        }
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };
  return (
    <Formik
      initialValues={initialValues}
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

const TaskCreation = ({
  paginationOptions,
}: {
  paginationOptions: TasksLinesPaginationQuery$variables;
}) => {
  const { t } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_tasks__caseTasks', paginationOptions, 'taskAdd');
  return (
    <Drawer
      title={t('Create a task')}
      variant={DrawerVariant.create}
    >
      <TaskCreationForm updater={updater} />
    </Drawer>
  );
};

export default TaskCreation;
