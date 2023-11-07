import React, { Component, FunctionComponent, useState } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import { compose } from 'ramda';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import MenuItem from '@mui/material/MenuItem';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { Option } from '@components/common/form/ReferenceField';
import { DataSourceCreationForm } from '@components/techniques/data_sources/DataSourceCreation';
import inject18n, { useFormatter } from '../../../../components/i18n';
import { commitMutation, handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import MarkdownField from '../../../../components/MarkdownField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { Theme } from '../../../../components/Theme';
import { insertNode } from '../../../../utils/store';

const useStyles = makeStyles<Theme>((theme) => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
}));

const locationMutation = graphql`
  mutation LocationCreationMutation($input: LocationAddInput!) {
    locationAdd(input: $input) {
      id
      standard_id
      name
      entity_type
    }
  }
`;

interface LocationCreationProps {
  contextual?: boolean
  display?: boolean
  inputValue?: string | undefined
  onlyAuthors: boolean
}

interface LocationCreationFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  inputValue?: string;
  defaultCreatedBy?: Option;
  defaultMarkingDefinitions?: Option[];
  defaultConfidence?: number;
}

const locationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  type: Yup.string().required(t('This field is required')),
});

const LocationCreationForm: FunctionComponent<LocationCreationFormProps> = ({
  inputValue,
  onlyAuthors,
  onReset,
  onCompleted,
  updater,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [commit] = useMutation(locationMutation);

  const onSubmit = (values, { setSubmitting, resetForm, setErrors }) => {
    commit({
      variables: {
        input: values,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'locationAdd');
        }
      },
      onError: (error: Error) => {
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

  return (
    <Formik
      enableReinitialize={true}
      initialValues={{
        name: inputValue,
        description: '',
        type: '',
      }}
      validationSchema={locationValidation(t)}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            detectDuplicate={['Organization', 'Individual']}
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
            component={SelectField}
            variant="standard"
            name="type"
            label={t('Entity type')}
            fullWidth={true}
            containerstyle={fieldSpacingContainerStyle}
          >
            {!onlyAuthors && (
              <MenuItem value="Sector">{t('Sector')}</MenuItem>
            )}
            <MenuItem value="Organization">
              {t('Organization')}
            </MenuItem>
            {!onlyAuthors && (
              <MenuItem value="Region">{t('Region')}</MenuItem>
            )}
            {!onlyAuthors && (
              <MenuItem value="Country">{t('Country')}</MenuItem>
            )}
            {!onlyAuthors && (
              <MenuItem value="City">{t('City')}</MenuItem>
            )}
            <MenuItem value="Individual">{t('Individual')}</MenuItem>
          </Field>
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

const LocationCreation: FunctionComponent<LocationCreationProps> = ({
  contextual,
  display,
  inputValue,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_locations',
    'locationAdd',
  );

  const renderClassic = () => (
    <Drawer
      title={t('Add a location')}
      variant={DrawerVariant.create}
    >
      {({ onClose }) => (
        <LocationCreationForm
          inputValue={inputValue}
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );

  const renderContextual = () => (
    <div style={{ display: display ? 'block' : 'none' }}>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButtonContextual}
      >
        <Add />
      </Fab>
      <Dialog open={open} onClose={handleClose} PaperProps={{ elevation: 1 }}>
        <DialogTitle>{t('Add a location')}</DialogTitle>
        <DialogContent>
          <LocationCreationForm
            inputValue={inputValue}
            updater={updater}
            onCompleted={handleClose}
            onReset={handleClose}
          />
        </DialogContent>
      </Dialog>
    </div>
  );

  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default LocationCreation;
