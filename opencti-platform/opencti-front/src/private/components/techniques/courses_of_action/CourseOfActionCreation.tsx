import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Button from '@mui/material/Button';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import { CoursesOfActionLinesPaginationQuery$variables } from '@components/techniques/__generated__/CoursesOfActionLinesPaginationQuery.graphql';
import ConfidenceField from '@components/common/form/ConfidenceField';
import useHelper from 'src/utils/hooks/useHelper';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import type { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { CourseOfActionCreationMutation, CourseOfActionCreationMutation$variables } from './__generated__/CourseOfActionCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  createButtonContextual: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const courseOfActionMutation = graphql`
  mutation CourseOfActionCreationMutation($input: CourseOfActionAddInput!) {
    courseOfActionAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      confidence
      ...CoursesOfActionLine_node
    }
  }
`;

const COURSE_OF_ACTION_TYPE = 'Course-Of-Action';

interface CourseOfActionAddInput {
  name: string
  description: string
  confidence: number | undefined
  createdBy: Option | undefined
  objectMarking: Option[]
  objectLabel: Option[]
  externalReferences: { value: string }[]
  file: File | undefined
}

interface CourseOfActionFormProps {
  updater?: (store: RecordSourceSelectorProxy, key: string) => void;
  paginationOptions?: CoursesOfActionLinesPaginationQuery$variables;
  display?: boolean;
  contextual?: boolean;
  onReset?: () => void;
  inputValue?: string;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
}

export const CourseOfActionCreationForm: FunctionComponent<CourseOfActionFormProps> = ({
  updater,
  onReset,
  inputValue,
  onCompleted,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const basicShape = {
    name: Yup.string()
      .min(2)
      .required(t_i18n('This field is required')),
    description: Yup.string()
      .nullable(),
    confidence: Yup.number().nullable(),
  };
  const courseOfActionValidator = useSchemaCreationValidation(
    COURSE_OF_ACTION_TYPE,
    basicShape,
  );

  const [commit] = useApiMutation<CourseOfActionCreationMutation>(
    courseOfActionMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Course-Of-Action')} ${t_i18n('successfully created')}` },
  );

  const onSubmit: FormikConfig<CourseOfActionAddInput>['onSubmit'] = (
    values,
    {
      setSubmitting,
      setErrors,
      resetForm,
    },
  ) => {
    const input: CourseOfActionCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      confidence: parseInt(String(values.confidence), 10),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'courseOfActionAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };

  const initialValues = useDefaultValues(
    COURSE_OF_ACTION_TYPE,
    {
      name: inputValue ?? '',
      description: '',
      confidence: undefined,
      createdBy: defaultCreatedBy,
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
      file: undefined,
    },
  );

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={courseOfActionValidator}
      onSubmit={onSubmit}
      onReset={onReset}
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
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            detectDuplicate={['Course-Of-Action']}
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
          <ConfidenceField
            entityType="Course-Of-Action"
            containerStyle={fieldSpacingContainerStyle}
          />
          <CreatedByField
            name="createdBy"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ExternalReferencesField
            name="externalReferences"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
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
  );
};

const CourseOfActionCreation: FunctionComponent<CourseOfActionFormProps> = ({
  paginationOptions,
  contextual,
  display,
  inputValue,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_coursesOfAction',
    paginationOptions,
    'courseOfActionAdd',
  );
  const CreateCourseOfActionControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='Course-Of-Action' {...props} />
  );
  const CreateCourseOfActionControlledDialContextual = CreateCourseOfActionControlledDial({
    onOpen: handleOpen,
    onClose: () => {},
  });
  const renderClassic = () => {
    return (
      <Drawer
        title={t_i18n('Create a course of action')}
        variant={isFABReplaced ? undefined : DrawerVariant.create}
        controlledDial={isFABReplaced ? CreateCourseOfActionControlledDial : undefined}
      >
        {({ onClose }) => (
          <CourseOfActionCreationForm
            inputValue={inputValue}
            updater={updater}
            onCompleted={onClose}
            onReset={onClose}
          />
        )}
      </Drawer>
    );
  };
  const renderContextual = () => {
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        {isFABReplaced
          ? (
            <div style={{ marginTop: '5px' }}>
              {CreateCourseOfActionControlledDialContextual}
            </div>
          ) : (
            <Fab
              onClick={handleOpen}
              color="secondary"
              aria-label="Add"
              className={classes.createButtonContextual}
            >
              <Add />
            </Fab>
          )
        }
        <Dialog open={open} onClose={handleClose} PaperProps={{ elevation: 1 }}>
          <DialogTitle>{t_i18n('Create a course of action')}</DialogTitle>
          <DialogContent>
            <CourseOfActionCreationForm
              inputValue={inputValue}
              updater={updater}
              onCompleted={handleClose}
              onReset={handleClose}
            />
          </DialogContent>
        </Dialog>
      </div>
    );
  };

  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default CourseOfActionCreation;
