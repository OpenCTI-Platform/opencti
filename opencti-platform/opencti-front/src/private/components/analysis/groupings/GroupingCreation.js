import React, { useState } from 'react';
import { Form, Formik, Field } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import {
  commitMutation,
  handleErrorInForm,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import CreatedByField from '../../common/form/CreatedByField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';

const useStyles = makeStyles((theme) => ({
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
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
}));

const groupingMutation = graphql`
  mutation GroupingCreationMutation($input: GroupingAddInput!) {
    groupingAdd(input: $input) {
      id
      name
      entity_type
      description
      ...GroupingLine_node
    }
  }
`;

export const GroupingCreationForm = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    confidence: Yup.number().nullable(),
    context: Yup.string().required(t('This field is required')),
    description: Yup.string().nullable(),
  };
  const groupingValidator = useSchemaCreationValidation('Grouping', basicShape);
  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    const adaptedValues = R.evolve(
      {
        confidence: () => parseInt(values.confidence, 10),
        createdBy: R.path(['value']),
        objectMarking: R.pluck('value'),
        objectLabel: R.pluck('value'),
        externalReferences: R.pluck('value'),
      },
      values,
    );
    commitMutation({
      mutation: groupingMutation,
      variables: {
        input: adaptedValues,
      },
      updater: (store, response) => {
        if (updater) {
          updater(store, 'groupingAdd', response.groupingAdd);
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };

  return (
    <Formik
      initialValues={{
        name: '',
        confidence: defaultConfidence ?? 75,
        context: '',
        description: '',
        createdBy: defaultCreatedBy ?? '',
        objectMarking: defaultMarkingDefinitions ?? [],
        objectLabel: [],
        externalReferences: [],
      }}
      validationSchema={groupingValidator}
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
          />
          <ConfidenceField
            entityType="Grouping"
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t('Context')}
            type="grouping-context-ov"
            name="context"
            multiple={false}
            containerStyle={fieldSpacingContainerStyle}
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
  );
};

const GroupingCreation = ({ paginationOptions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const onReset = () => setOpen(false);
  const updater = (store) => insertNode(store, 'Pagination_groupings', paginationOptions, 'groupingAdd');
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
          <Typography variant="h6">{t('Create a grouping')}</Typography>
        </div>
        <div className={classes.container}>
          <GroupingCreationForm
            updater={updater}
            onCompleted={onReset}
            onReset={onReset}
          />
        </div>
      </Drawer>
    </div>
  );
};

export default GroupingCreation;
