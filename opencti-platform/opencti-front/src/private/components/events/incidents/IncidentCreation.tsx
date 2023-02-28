import React, { useState } from 'react';
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
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { insertNode } from '../../../../utils/store';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { isEmptyField } from '../../../../utils/utils';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import {
  IncidentsCardsAndLinesPaginationQuery$variables,
} from './__generated__/IncidentsCardsAndLinesPaginationQuery.graphql';
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

const IncidentMutation = graphql`
  mutation IncidentCreationMutation($input: IncidentAddInput!) {
    incidentAdd(input: $input) {
      ...IncidentLine_node
    }
  }
`;

interface IncidentAddInput {
  name: string
  description: string
  confidence: number
  incident_type: string
  severity: string
  source: string
  createdBy: Option | undefined
  objectMarking: Option[]
  objectLabel: Option[]
  objectAssignee: Option[]
  externalReferences: Option[]
}

const IncidentCreation = ({ paginationOptions }: { paginationOptions: IncidentsCardsAndLinesPaginationQuery$variables }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [commit] = useMutation(IncidentMutation);

  const basicShape = {
    name: Yup.string().required(t('This field is required')),
    confidence: Yup.number(),
    incident_type: Yup.string(),
    severity: Yup.string(),
    source: Yup.string(),
    description: Yup.string().nullable(),
  };
  const incidentValidator = useYupSchemaBuilder('Incident', basicShape);

  const onSubmit: FormikConfig<IncidentAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const cleanedValues = isEmptyField(values.severity) ? R.dissoc('severity', values) : values;
    const finalValues = {
      ...cleanedValues,
      confidence: parseInt(String(cleanedValues.confidence), 10),
      createdBy: cleanedValues.createdBy?.value,
      objectMarking: cleanedValues.objectMarking.map((v) => v.value),
      objectAssignee: cleanedValues.objectAssignee.map(({ value }) => value),
      objectLabel: cleanedValues.objectLabel.map(({ value }) => value),
      externalReferences: cleanedValues.externalReferences.map(({ value }) => value),
    };
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => insertNode(
        store,
        'Pagination_incidents',
        paginationOptions,
        'incidentAdd',
      ),
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        setOpen(false);
      },
    });
  };
  return (
    <div>
      <Fab onClick={() => setOpen(true)}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}>
        <Add />
      </Fab>
      <Drawer open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={() => setOpen(false)}>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={() => setOpen(false)}
            size="large"
            color="primary">
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create an incident')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik<IncidentAddInput>
            initialValues={{
              name: '',
              confidence: 75,
              incident_type: '',
              severity: '',
              source: '',
              description: '',
              createdBy: undefined,
              objectMarking: [],
              objectAssignee: [],
              objectLabel: [],
              externalReferences: [],
            }}
            validationSchema={incidentValidator}
            onSubmit={onSubmit}
            onReset={() => setOpen(false)}
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
                  detectDuplicate={['Incident']}
                />
                <ConfidenceField
                  name="confidence"
                  label={t('Confidence')}
                  fullWidth={true}
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
                  component={MarkDownField}
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
                  style={{ marginTop: 20, width: '100%' }}
                />
                <CreatedByField
                  name="createdBy"
                  style={{ marginTop: 20, width: '100%' }}
                  setFieldValue={setFieldValue}
                />
                <ObjectLabelField
                  name="objectLabel"
                  style={{ marginTop: 20, width: '100%' }}
                  setFieldValue={setFieldValue}
                  values={values.objectLabel}
                />
                <ObjectMarkingField
                  name="objectMarking"
                  style={{ marginTop: 20, width: '100%' }}
                />
                <ExternalReferencesField
                  name="externalReferences"
                  style={{ marginTop: 20, width: '100%' }}
                  setFieldValue={setFieldValue}
                  values={values.externalReferences}
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
