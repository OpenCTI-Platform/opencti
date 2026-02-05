import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import {
  LocationCreationMutation,
  LocationCreationMutation$data,
  LocationCreationMutation$variables,
} from '@components/common/location/__generated__/LocationCreationMutation.graphql';
import MenuItem from '@mui/material/MenuItem';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import TextField from '../../../../components/TextField';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import MarkdownField from '../../../../components/fields/MarkdownField';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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
          <FormButtonContainer>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
            >
              {t_i18n('Create')}
            </Button>
          </FormButtonContainer>
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
        <Button
          onClick={handleOpen}
          color="secondary"
          aria-label="Add"
        >
          {t_i18n('Create Location')}
        </Button>
        <Dialog
          open={open}
          onClose={handleClose}
          title={t_i18n('Add a location')}
        >
          <LocationCreationForm
            inputValue={inputValue}
            updater={updater}
            onCompleted={handleClose}
            onReset={handleClose}
          />
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
