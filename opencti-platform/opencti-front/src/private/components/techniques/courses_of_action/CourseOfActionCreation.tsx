import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { CoursesOfActionLinesPaginationQuery$variables } from '@components/techniques/__generated__/CoursesOfActionLinesPaginationQuery.graphql';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import type { Theme } from '../../../../components/Theme';
import { CourseOfActionCreationMutation, CourseOfActionCreationMutation$variables } from './__generated__/CourseOfActionCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

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

const courseOfActionMutation = graphql`
  mutation CourseOfActionCreationMutation($input: CourseOfActionAddInput!) {
    courseOfActionAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
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
  name: string;
  description: string;
  confidence: number | undefined;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  file: File | undefined;
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
  const { mandatoryAttributes } = useIsMandatoryAttribute(COURSE_OF_ACTION_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string()
      .nullable(),
    confidence: Yup.number().nullable(),
  }, mandatoryAttributes);
  const courseOfActionValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
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
    <Formik<CourseOfActionAddInput>
      initialValues={initialValues}
      validationSchema={courseOfActionValidator}
      validateOnChange={true}
      validateOnBlur={true}
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
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            detectDuplicate={['Course-Of-Action']}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
          />
          <ConfidenceField
            entityType="Course-Of-Action"
            containerStyle={fieldSpacingContainerStyle}
          />
          <CreatedByField
            name="createdBy"
            required={(mandatoryAttributes.includes('createdBy'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            required={(mandatoryAttributes.includes('objectLabel'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={(mandatoryAttributes.includes('objectMarking'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ExternalReferencesField
            name="externalReferences"
            required={(mandatoryAttributes.includes('externalReferences'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
          <div className={classes.buttons}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
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
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_coursesOfAction',
    paginationOptions,
    'courseOfActionAdd',
  );
  const CreateCourseOfActionControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Course-Of-Action" {...props} />
  );
  const CreateCourseOfActionControlledDialContextual = CreateCourseOfActionControlledDial({
    onOpen: handleOpen,
    onClose: () => { },
  });
  const renderClassic = () => {
    return (
      <Drawer
        title={t_i18n('Create a course of action')}
        controlledDial={CreateCourseOfActionControlledDial}
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
        <div style={{ marginTop: '5px' }}>
          {CreateCourseOfActionControlledDialContextual}
        </div>
        <Dialog open={open} onClose={handleClose} slotProps={{ paper: { elevation: 1 } }}>
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
