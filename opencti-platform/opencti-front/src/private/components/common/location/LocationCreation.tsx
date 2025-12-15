import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Button from '@common/button/Button';
import MenuItem from '@mui/material/MenuItem';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import {
  LocationCreationMutation,
  LocationCreationMutation$data,
  LocationCreationMutation$variables,
} from '@components/common/location/__generated__/LocationCreationMutation.graphql';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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

const locationMutation = graphql`
  mutation LocationCreationMutation($input: LocationAddInput!) {
    locationAdd(input: $input) {
      id
      standard_id
      name
      entity_type
      parent_types
    }
  }
`;

interface LocationAddInput {
  name: string;
  description: string;
  type: string;
}

interface LocationCreationFormProps {
  updater: (store: RecordSourceSelectorProxy) => void;
  onReset?: () => void;
  display?: boolean;
  contextual?: boolean;
  onCompleted?: () => void;
  inputValue: string;
  creationCallback?: (data: LocationCreationMutation$data) => void;
  onlyAuthors?: boolean;
}

const locations = [
  'Administrative-Area',
  'Region',
  'Country',
  'City',
  'Position',
];

const locationValidation = (t: (name: string | object) => string) => Yup.object().shape({
  name: Yup.string().trim().required(t('This field is required')),
  description: Yup.string().nullable(),
  type: Yup.string().trim().required(t('This field is required')),
});

const LocationCreationForm: FunctionComponent<LocationCreationFormProps> = ({
  inputValue,
  onlyAuthors,
  onReset,
  onCompleted,
  contextual,
  creationCallback,
  updater,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const [commit] = useApiMutation<LocationCreationMutation>(locationMutation);

  const onSubmit: FormikConfig<LocationAddInput>['onSubmit'] = (
    values,
    {
      setSubmitting,
      resetForm,
      setErrors,
    },
  ) => {
    const input: LocationCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      type: values.type,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => updater(store),
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        if (contextual && creationCallback) {
          creationCallback(response);
        }
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
      validationSchema={locationValidation(t_i18n)}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({
        submitForm,
        handleReset,
        isSubmitting,
      }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            detectDuplicate={['Organization', 'Individual']}
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
          <Field
            component={SelectField}
            variant="standard"
            name="type"
            label={t_i18n('Entity type')}
            fullWidth={true}
            containerstyle={fieldSpacingContainerStyle}
          >
            {!onlyAuthors && locations.map((location, idx) => (
              <MenuItem key={idx} value={location}>{t_i18n(location)}</MenuItem>
            ))}
          </Field>
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

const LocationCreation: FunctionComponent<LocationCreationFormProps> = ({
  contextual,
  display,
  inputValue,
  updater,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  const renderClassic = () => {
    return (
      <Drawer
        title={t_i18n('Add a location')}
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
  };

  const renderContextual = () => {
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        <Fab
          onClick={handleOpen}
          color="secondary"
          aria-label="Add"
          className={classes.createButtonContextual}
        >
          <Add />
        </Fab>
        <Dialog open={open} onClose={handleClose} slotProps={{ paper: { elevation: 1 } }}>
          <DialogTitle>{t_i18n('Add a location')}</DialogTitle>
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
  };
  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default LocationCreation;
