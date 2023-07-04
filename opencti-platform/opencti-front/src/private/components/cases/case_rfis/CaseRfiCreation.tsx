import { Add, Close } from '@mui/icons-material';
import Button from '@mui/material/Button';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { SimpleFileUpload } from 'formik-mui';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import { useHistory } from 'react-router-dom';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import TextField from '../../../../components/TextField';
import { Theme } from '../../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import CaseTemplateField from '../../common/form/CaseTemplateField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CreatedByField from '../../common/form/CreatedByField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { Option } from '../../common/form/ReferenceField';
import {
  CaseRfiAddInput,
  CaseRfiCreationCaseMutation,
} from './__generated__/CaseRfiCreationCaseMutation.graphql';
import { CaseRfiLinesCasesPaginationQuery$variables } from './__generated__/CaseRfiLinesCasesPaginationQuery.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import RichTextField from '../../../../components/RichTextField';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
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
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

const caseRfiMutation = graphql`
  mutation CaseRfiCreationCaseMutation($input: CaseRfiAddInput!) {
    caseRfiAdd(input: $input) {
      id
      standard_id
      entity_type
      parent_types
      name
      description
      ...CaseRfiLineCase_node
    }
  }
`;

interface FormikCaseRfiAddInput {
  name: string;
  confidence: number | undefined;
  description: string;
  content: string;
  file: File | undefined;
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectAssignee: Option[];
  objectParticipant: Option[];
  objectLabel: Option[];
  externalReferences: Option[];
  created: Date | null;
  information_types: string[];
  severity: string;
  priority: string;
  caseTemplates?: Option[];
}

interface CaseRfiFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
    response: { id: string; name: string } | null
  ) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultConfidence?: number;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
}

const CASE_RFI_TYPE = 'Case-Rfi';

export const CaseRfiCreationForm: FunctionComponent<CaseRfiFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const history = useHistory();
  const [mapAfter, setMapAfter] = useState<boolean>(false);
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
  };
  const caseRfiValidator = useSchemaCreationValidation(
    CASE_RFI_TYPE,
    basicShape,
  );
  const [commit] = useMutation<CaseRfiCreationCaseMutation>(caseRfiMutation);
  const onSubmit: FormikConfig<FormikCaseRfiAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const input: CaseRfiAddInput = {
      name: values.name,
      description: values.description,
      content: values.content,
      created: values.created,
      information_types: values.information_types,
      severity: values.severity,
      priority: values.priority,
      caseTemplates: values.caseTemplates?.map(({ value }) => value),
      confidence: parseInt(String(values.confidence), 10),
      objectAssignee: values.objectAssignee.map(({ value }) => value),
      objectParticipant: values.objectParticipant.map(({ value }) => value),
      objectMarking: values.objectMarking.map(({ value }) => value),
      objectLabel: values.objectLabel.map(({ value }) => value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      createdBy: values.createdBy?.value,
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store, response) => {
        if (updater) {
          updater(store, 'caseRfiAdd', response.caseRfiAdd);
        }
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
        if (mapAfter) {
          history.push(
            `/dashboard/cases/rfis/${response.caseRfiAdd?.id}/knowledge/content`,
          );
        }
      },
    });
  };

  const initialValues = useDefaultValues<FormikCaseRfiAddInput>(CASE_RFI_TYPE, {
    name: '',
    confidence: defaultConfidence,
    description: '',
    content: '',
    severity: '',
    priority: '',
    caseTemplates: [],
    created: null,
    information_types: [],
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectAssignee: [],
    objectParticipant: [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  });

  return (
    <Formik<FormikCaseRfiAddInput>
      initialValues={initialValues}
      validationSchema={caseRfiValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            detectDuplicate={['Case-Rfi']}
            style={{ marginBottom: '20px' }}
          />
          <Field
            component={DateTimePickerField}
            name="created"
            TextFieldProps={{
              label: t('Request For Information Date'),
              variant: 'standard',
              fullWidth: true,
            }}
          />
          <OpenVocabField
            label={t('Request for information type')}
            type="request_for_information_types_ov"
            name="information_types"
            multiple
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t('Severity')}
            type="case_severity_ov"
            name="severity"
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t('Priority')}
            type="case_priority_ov"
            name="priority"
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
          />
          <CaseTemplateField
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
          />
          <ConfidenceField
            entityType="Case-Rfi"
            containerStyle={fieldSpacingContainerStyle}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={RichTextField}
            name="content"
            label={t('Content')}
            fullWidth={true}
            style={{
              ...fieldSpacingContainerStyle,
              minHeight: 200,
              height: 200,
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
          />
          <ExternalReferencesField
            name="externalReferences"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <Field
            component={SimpleFileUpload}
            name="file"
            label={t('Associated file')}
            FormControlProps={{ style: fieldSpacingContainerStyle }}
            InputLabelProps={{ fullWidth: true, variant: 'standard' }}
            InputProps={{ fullWidth: true, variant: 'standard' }}
            fullWidth={true}
          />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
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
            {values.content.length > 0 && (
              <Button
                variant="contained"
                color="success"
                onClick={() => {
                  setMapAfter(true);
                  submitForm();
                }}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t('Create and map')}
              </Button>
            )}
          </div>
        </Form>
      )}
    </Formik>
  );
};

const CaseRfiCreation = ({
  paginationOptions,
}: {
  paginationOptions: CaseRfiLinesCasesPaginationQuery$variables;
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onReset = () => handleClose();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_case_caseRfis',
    paginationOptions,
    'caseRfiAdd',
  );

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
        disableEnforceFocus={true}
      >
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
          <Typography variant="h6">
            {t('Create a request for information')}
          </Typography>
        </div>
        <div className={classes.container}>
          <CaseRfiCreationForm
            updater={updater}
            onCompleted={() => handleClose()}
            onReset={onReset}
          />
        </div>
      </Drawer>
    </div>
  );
};

export default CaseRfiCreation;
