import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import { SimpleFileUpload } from 'formik-mui';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import Fab from '@mui/material/Fab';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import { Theme } from '../../../../components/Theme';
import { IncidentCreationCaseMutation$variables } from './__generated__/IncidentCreationCaseMutation.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { IncidentsLinesCasesPaginationQuery$variables } from './__generated__/IncidentsLinesCasesPaginationQuery.graphql';
import { insertNode } from '../../../../utils/store';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import ConfidenceField from '../../common/form/ConfidenceField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { useYupSchemaBuilder } from '../../../../utils/hooks/useEntitySettings';

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

const incidentMutation = graphql`
  mutation IncidentCreationCaseMutation($input: CaseAddInput!) {
    caseAdd(input: $input) {
      ...IncidentLineCase_node
    }
  }
`;

interface FormikCaseAddInput {
  name: string
  confidence: number
  severity: string
  priority: string
  description: string
  file: File | undefined
  createdBy?: { value: string; label?: string }
  objectMarking: { value: string }[]
  objectAssignee: { value: string }[]
  objectLabel: { value: string }[]
  externalReferences: { value: string }[]
}

const IncidentCreation = ({
  paginationOptions,
}: {
  paginationOptions: IncidentsLinesCasesPaginationQuery$variables;
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);

  const basicShape = {
    description: Yup.string().nullable(),
  };
  const caseValidator = useYupSchemaBuilder('Case', basicShape);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const [commit] = useMutation(incidentMutation);
  const onSubmit: FormikConfig<FormikCaseAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const finalValues: IncidentCreationCaseMutation$variables['input'] = {
      name: values.name,
      case_type: 'incident',
      description: values.description,
      severity: values.severity,
      priority: values.priority,
      objectAssignee: values.objectAssignee.map(({ value }) => value),
      objectMarking: values.objectMarking.map(({ value }) => value),
      objectLabel: values.objectLabel.map(({ value }) => value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      createdBy: values.createdBy?.value,
    };
    if (values.file) {
      finalValues.file = values.file;
    }
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_incidents_cases',
          paginationOptions,
          'caseAdd',
        );
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };
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
          <Typography variant="h6">{t('Create a case (incident)')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik<FormikCaseAddInput>
            initialValues={{
              name: '',
              confidence: 75,
              description: '',
              severity: '',
              priority: '',
              createdBy: { value: '', label: '' },
              objectMarking: [],
              objectAssignee: [],
              objectLabel: [],
              externalReferences: [],
              file: undefined,
            }}
            validationSchema={caseValidator}
            onSubmit={onSubmit}
            onReset={handleClose}
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
                  label={t('Name')}
                  fullWidth={true}
                  detectDuplicate={['Case']}
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
                <ConfidenceField
                  name="confidence"
                  label={t('Confidence')}
                  fullWidth={true}
                  containerStyle={fieldSpacingContainerStyle}
                />
                <Field
                  component={MarkDownField}
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={fieldSpacingContainerStyle}
                />
                <ObjectAssigneeField
                  name="objectAssignee"
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
        </div>
      </Drawer>
    </div>
  );
};

export default IncidentCreation;
