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
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig, FormikErrors } from 'formik/dist/types';
import { Box, Tab, Tabs } from '@mui/material';
import Badge, { BadgeProps } from '@mui/material/Badge';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { insertNode } from '../../../../utils/store';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { Option } from '../../common/form/ReferenceField';
import { Theme } from '../../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import {
  ThreatActorsIndividualCardsPaginationQuery$variables,
} from './__generated__/ThreatActorsIndividualCardsPaginationQuery.graphql';
import {
  HeightTupleInputValues,
  ThreatActorIndividualCreationMutation,
  ThreatActorIndividualCreationMutation$variables,
  WeightTupleInputValues,
} from './__generated__/ThreatActorIndividualCreationMutation.graphql';
import DatePickerField from '../../../../components/DatePickerField';
import HeightField from '../../common/form/mcas/HeightField';
import WeightField from '../../common/form/mcas/WeightField';
import CountryPickerField from '../../common/form/mcas/CountryPickerField';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import { styled } from '@mui/material/styles';

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
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

interface ErrorBadgeProps extends BadgeProps {
  errors?: FormikErrors<ThreatActorIndividualAddInput>;
  width?: number,
}

const ErrorBadge = styled(Badge)<ErrorBadgeProps>(({ errors = {}, width = 80 }) => ({
  color: Object.keys(errors).length > 0 ? 'red' : 'inherit',
  width: Object.keys(errors).length > 0 ? width : 'auto',
  '& .MuiBadge-badge': {
    color: 'white',
    backgroundColor: 'red',
  },
}));

const ThreatActorIndividualMutation = graphql`
  mutation ThreatActorIndividualCreationMutation($input: ThreatActorIndividualAddInput!) {
    threatActorIndividualAdd(input: $input) {
      id
      name
      description
      entity_type
      parent_types
      ...ThreatActorIndividualCard_node
    }
  }
`;

const THREAT_ACTOR_INDIVIDUAL_TYPE = 'Threat-Actor-Individual';

interface ThreatActorIndividualAddInput {
  name: string;
  threat_actor_types: string[];
  confidence: number | undefined;
  description: string;
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: { value: string }[];
  file: File | undefined;
  bornIn: string | null
  nationality: string | null
  ethnicity: string | null
  date_of_birth: Date | null
  gender: string | null
  marital_status: string | null
  job_title: string | undefined
  eye_color: string | null
  hair_color: string | null
  height: HeightTupleInputValues[]
  weight: WeightTupleInputValues[]
}

interface ThreatActorIndividualFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  inputValue?: string;
}

export const ThreatActorIndividualCreationForm: FunctionComponent<
ThreatActorIndividualFormProps
> = ({
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
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (_: React.SyntheticEvent, value: number) => setCurrentTab(value);
  const basicShape = {
    name: Yup.string().required(t('This field is required')),
    threat_actor_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    date_of_birth: Yup.date()
      .nullable()
      .typeError(t('The value must be a date (yyyy-MM-dd)')),
    bornIn: Yup.string().nullable(),
    nationality: Yup.string().nullable(),
    ethnicity: Yup.string().nullable(),
    gender: Yup.string()
      .nullable()
      .typeError(t('The value must be a string')),
    marital_status: Yup.string()
      .nullable()
      .typeError(t('The value must be a string')),
    job_title: Yup.string()
      .max(250, t('The value is too long')),
    eye_color: Yup.string().nullable(),
    hair_color: Yup.string().nullable(),
    height: Yup.array().of(
      Yup.object().shape({
        height_cm: Yup.number().min(0).nullable()
          .typeError(t('The value must be a number')),
        date_seen: Yup.date().nullable()
          .typeError(t('The value must be a date (yyyy-MM-dd)')),
      }),
    ),
    weight: Yup.array().of(
      Yup.object().shape({
        weight_kg: Yup.number().min(0).nullable()
          .typeError(t('The value must be a number')),
        date_seen: Yup.date().nullable()
          .typeError(t('The value must be a date (yyyy-MM-dd)')),
      }),
    ),
  };
  const threatActorIndividualValidator = useSchemaCreationValidation(
    THREAT_ACTOR_INDIVIDUAL_TYPE,
    basicShape,
  );

  const [commit] = useMutation<ThreatActorIndividualCreationMutation>(ThreatActorIndividualMutation);

  const onSubmit: FormikConfig<ThreatActorIndividualAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: ThreatActorIndividualCreationMutation$variables['input'] = {
      name: values?.name,
      description: values?.description,
      threat_actor_types: values?.threat_actor_types,
      confidence: parseInt(String(values?.confidence), 10),
      createdBy: values?.createdBy?.value,
      objectMarking: values?.objectMarking.map((v) => v.value),
      objectLabel: values?.objectLabel.map((v) => v.value),
      externalReferences: values?.externalReferences.map(({ value }) => value),
      file: values?.file,
      bornIn: values?.bornIn,
      nationality: values?.nationality,
      ethnicity: values?.ethnicity,
      date_of_birth: values?.date_of_birth,
      gender: values?.gender,
      marital_status: values?.marital_status,
      job_title: values?.job_title,
      eye_color: values?.eye_color,
      hair_color: values?.hair_color,
      height: values?.height,
      weight: values?.weight,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'threatActorIndividualAdd');
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

  const initialValues = useDefaultValues(THREAT_ACTOR_INDIVIDUAL_TYPE, {
    name: inputValue ?? '',
    threat_actor_types: [],
    confidence: defaultConfidence,
    description: '',
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
    bornIn: null,
    nationality: null,
    ethnicity: null,
    date_of_birth: null,
    gender: null,
    marital_status: null,
    job_title: undefined,
    eye_color: null,
    hair_color: null,
    height: [],
    weight: [],
  });

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={threatActorIndividualValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values, errors }) => (
        <Form>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={handleChangeTab}>
              <Tab id='create-overview' label={
                <ErrorBadge badgeContent={Object.keys(errors).length}
                  errors={errors}
                >
                  {t('Overview')}
                </ErrorBadge>}
              />
              <Tab id='threat-demographics' label={t('Demographics')} />
              <Tab id='threat-bio' label={t('Biographics')} />
            </Tabs>
          </Box>
          {currentTab === 0 && (
            <div>
              <Field
                component={TextField}
                name="name"
                label={t('Name')}
                fullWidth={true}
                detectDuplicate={[
                  'Threat-Actor',
                  'Intrusion-Set',
                  'Campaign',
                  'Malware',
                ]}
              />
              <OpenVocabField
                type="threat-actor-individual-type-ov"
                name="threat_actor_types"
                label={t('Threat actor types')}
                multiple={true}
                containerStyle={{ width: '100%', marginTop: 20 }}
                onChange={setFieldValue}
              />
              <ConfidenceField
                entityType="Threat-Actor-Individual"
                containerStyle={{ width: '100%', marginTop: 20 }}
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
              <CreatedByField
                name="createdBy"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
              <ObjectLabelField
                name="objectLabel"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
                values={values?.objectLabel}
              />
              <ObjectMarkingField
                name="objectMarking"
                style={fieldSpacingContainerStyle}
              />
              <ExternalReferencesField
                name="externalReferences"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
                values={values?.externalReferences}
              />
              <CustomFileUploader setFieldValue={setFieldValue}
              />
            </div>
          )}
          {currentTab === 1 && (
            <div>
              <CountryPickerField
                id="PlaceOfBirth"
                name="bornIn"
                multi={false}
                initialValues={values?.bornIn || undefined}
                label={t('Place of Birth')}
                style={fieldSpacingContainerStyle}
                handleChange={setFieldValue}
              />
              <CountryPickerField
                id="Nationality"
                name="nationality"
                multi={false}
                initialValues={values?.nationality || undefined}
                label={t('Nationality')}
                style={fieldSpacingContainerStyle}
                handleChange={setFieldValue}
              />
              <CountryPickerField
                id="Ethnicity"
                name="ethnicity"
                multi={false}
                initialValues={values?.ethnicity || undefined}
                label={t('Ethnicity')}
                style={fieldSpacingContainerStyle}
                handleChange={setFieldValue}
              />
              <Field
                id="DateOfBirth"
                component={DatePickerField}
                name="date_of_birth"
                onSubmit={setFieldValue}
                TextFieldProps={{
                  label: t('Date of Birth'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <OpenVocabField
                name="marital_status"
                label={t('Marital Status')}
                type="marital_status_ov"
                variant="edit"
                onChange={setFieldValue}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={[]}
              />
              <OpenVocabField
                name="gender"
                label={t('Gender')}
                type="gender_ov"
                variant="edit"
                onChange={setFieldValue}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={[]}
              />
              <Field
                component={MarkdownField}
                name="job_title"
                id="job_title"
                label={t('Job Title')}
                fullWidth={true}
                multiline={false}
                rows="1"
                style={{ marginTop: 20 }}
                onSubmit={setFieldValue}
              />
            </div>
          )}
          {currentTab === 2 && (
            <div>
              <OpenVocabField
                name="eye_color"
                label={t('Eye Color')}
                type="eye_color_ov"
                variant="edit"
                onChange={setFieldValue}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={[]}
              />
              <OpenVocabField
                name="hair_color"
                label={t('Hair Color')}
                type="hair_color_ov"
                variant="edit"
                onChange={setFieldValue}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={[]}
              />
              <HeightField
                id='new_height'
                name="height"
                values={values?.height}
                label={t('Heights')}
                variant="create"
                containerStyle={fieldSpacingContainerStyle}
              />
              <WeightField
                id='new_weight'
                name="weight"
                values={values?.weight}
                label={t('Weights')}
                variant="create"
                containerStyle={fieldSpacingContainerStyle}
              />
            </div>
          )}
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

const ThreatActorIndividualCreation = ({
  paginationOptions,
}: {
  paginationOptions: ThreatActorsIndividualCardsPaginationQuery$variables;
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_threatActorsIndividuals',
    paginationOptions,
    'threatActorIndividualAdd',
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
          <Typography variant="h6">{t('Create a threat actor individual')}</Typography>
        </div>
        <div className={classes.container}>
          <ThreatActorIndividualCreationForm
            updater={updater}
            onCompleted={handleClose}
            onReset={handleClose}
          />
        </div>
      </Drawer>
    </div>
  );
};

export default ThreatActorIndividualCreation;
