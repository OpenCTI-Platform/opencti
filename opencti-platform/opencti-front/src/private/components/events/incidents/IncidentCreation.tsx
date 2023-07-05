import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { SimpleFileUpload } from 'formik-mui';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { insertNode } from '../../../../utils/store';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { isEmptyField } from '../../../../utils/utils';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { IncidentsLinesPaginationQuery$variables } from './__generated__/IncidentsLinesPaginationQuery.graphql';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
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

const IncidentMutation = graphql`
  mutation IncidentCreationMutation($input: IncidentAddInput!) {
    incidentAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...IncidentLine_node
    }
  }
`;

interface IncidentAddInput {
  name: string;
  description: string;
  confidence: number | undefined;
  incident_type: string;
  severity: string;
  source: string;
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
  objectAssignee: Option[];
  objectParticipant: Option[];

  externalReferences: Option[];
  file: File | undefined;
}

interface IncidentCreationProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: Option;
  defaultMarkingDefinitions?: Option[];
  defaultConfidence?: number;
  inputValue?: string;
}

const INCIDENT_TYPE = 'Incident';

export const IncidentCreationForm: FunctionComponent<IncidentCreationProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [commit] = useMutation(IncidentMutation);
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    confidence: Yup.number().nullable(),
    incident_type: Yup.string().nullable(),
    severity: Yup.string().nullable(),
    source: Yup.string().nullable(),
    description: Yup.string().nullable(),
  };
  const incidentValidator = useSchemaCreationValidation(
    INCIDENT_TYPE,
    basicShape,
  );
  const onSubmit: FormikConfig<IncidentAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const cleanedValues = isEmptyField(values.severity)
      ? R.dissoc('severity', values)
      : values;
    const input = {
      ...cleanedValues,
      confidence: parseInt(String(cleanedValues.confidence), 10),
      createdBy: cleanedValues.createdBy?.value,
      objectMarking: cleanedValues.objectMarking.map((v) => v.value),
      objectAssignee: cleanedValues.objectAssignee.map(({ value }) => value),
      objectParticipant: cleanedValues.objectParticipant.map(({ value }) => value),
      objectLabel: cleanedValues.objectLabel.map(({ value }) => value),
      externalReferences: cleanedValues.externalReferences.map(
        ({ value }) => value,
      ),
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'incidentAdd');
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
  const initialValues = useDefaultValues<IncidentAddInput>(INCIDENT_TYPE, {
    name: inputValue ?? '',
    confidence: defaultConfidence,
    incident_type: '',
    severity: '',
    source: '',
    description: '',
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectAssignee: [],
    objectParticipant: [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  });
  return (
    <Formik<IncidentAddInput>
      initialValues={initialValues}
      validationSchema={incidentValidator}
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
            detectDuplicate={['Incident']}
          />
          <ConfidenceField
            entityType="Incident"
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t('Incident type')}
            type="incident-type-ov"
            name="incident_type"
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            onChange={setFieldValue}
          />
          <OpenVocabField
            label={t('Severity')}
            type="incident-severity-ov"
            name="severity"
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            onChange={setFieldValue}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="source"
            label={t('Source')}
            fullWidth={true}
            style={{ marginTop: 20 }}
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
            FormControlProps={{ style: { marginTop: 20, width: '100%' } }}
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
          </div>
        </Form>
      )}
    </Formik>
  );
};

const IncidentCreation = ({
  paginationOptions,
}: {
  paginationOptions: IncidentsLinesPaginationQuery$variables;
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const onReset = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_incidents', paginationOptions, 'incidentAdd');
  return (
    <div>
      <Fab
        onClick={() => setOpen(true)}
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
        onClose={() => setOpen(false)}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={() => setOpen(false)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create an incident')}</Typography>
        </div>
        <div className={classes.container}>
          <IncidentCreationForm
            updater={updater}
            onCompleted={onReset}
            onReset={onReset}
          />
        </div>
      </Drawer>
    </div>
  );
};

export default IncidentCreation;
