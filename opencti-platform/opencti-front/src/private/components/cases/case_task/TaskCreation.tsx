import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import TextField from '../../../../components/TextField';
import { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { Option } from '../../common/form/ReferenceField';
import {
  TaskCreationMutation,
  TaskCreationMutation$variables,
} from './__generated__/TaskCreationMutation.graphql';
import { TasksLinesPaginationQuery$variables } from './__generated__/TasksLinesPaginationQuery.graphql';
import { insertNode } from '../../../../utils/store';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
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
  dueDate?: Date | null
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
  onReset?: () => void;
  defaultMarkings?: { value: string, label: string }[]
}

const TaskCreationForm: FunctionComponent<TaskCreationProps> = ({
  updater,
  onReset,
  defaultMarkings,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable().max(5000, t('The value is too long')),
    dueDate: Yup.date().nullable(),
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
    dueDate: null,
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
      dueDate: values.dueDate,
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
      onReset={onReset}
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
            name="dueDate"
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
            component={MarkDownField}
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
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_tasks__caseTasks', paginationOptions, 'taskAdd');
  return (
    <div>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <div>
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={handleClose}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Create a task')}</Typography>
          </div>
          <div className={classes.container}>
            <TaskCreationForm
              updater={updater}
              onReset={handleClose}
            />
          </div>
        </div>
      </Drawer>
    </div>
  );
};

export default TaskCreation;
