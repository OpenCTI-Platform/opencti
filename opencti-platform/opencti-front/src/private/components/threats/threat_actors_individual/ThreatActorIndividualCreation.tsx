import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik, FormikErrors } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer from '@components/common/drawer/Drawer';
import { styled } from '@mui/material/styles';
import { Badge, BadgeProps } from '@mui/material';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import CountryField from '@components/common/form/CountryField';
import { Add } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$, handleErrorInForm } from '../../../../relay/environment';
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
import type { Theme } from '../../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import {
  MeasureInput,
  ThreatActorIndividualCreationMutation,
  ThreatActorIndividualCreationMutation$variables,
} from './__generated__/ThreatActorIndividualCreationMutation.graphql';
import { ThreatActorsIndividualCardsPaginationQuery$variables } from './__generated__/ThreatActorsIndividualCardsPaginationQuery.graphql';
import { HeightFieldAdd } from '../../common/form/HeightField';
import { WeightFieldAdd } from '../../common/form/WeightField';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useUserMetric from '../../../../utils/hooks/useUserMetric';
import DateTimePickerField from '../../../../components/DateTimePickerField';

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
  createBtn: {
    marginLeft: '10px',
    padding: '7px 10px',
  },
}));

interface ErrorBadgeProps extends BadgeProps {
  errors?: FormikErrors<ThreatActorIndividualAddInput>;
  width?: number;
}

const ErrorBadge = styled(Badge)<ErrorBadgeProps>(
  ({ errors = {}, width = 80 }) => ({
    color: Object.keys(errors).length > 0 ? 'red' : 'inherit',
    width: Object.keys(errors).length > 0 ? width : 'auto',
    '& .MuiBadge-badge': {
      color: 'white',
      backgroundColor: 'red',
    },
  }),
);

const ThreatActorIndividualMutation = graphql`
  mutation ThreatActorIndividualCreationMutation(
    $input: ThreatActorIndividualAddInput!
  ) {
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
  first_seen: Date | null;
  last_seen: Date | null;
  goals: string | null;
  sophistication: Option | null;
  resource_level: Option | null;
  roles: Option[] | null;
  primary_motivation: Option | null;
  secondary_motivations: Option[] | null;
  personal_motivations: Option[] | null;
  file: File | undefined;
  bornIn: Option | undefined;
  ethnicity: Option | undefined;
  date_of_birth: Date | null;
  gender: string | null;
  marital_status: string | null;
  job_title: string | undefined;
  eye_color: string | null;
  hair_color: string | null;
  height: MeasureInput[];
  weight: MeasureInput[];
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
  const { t_i18n } = useFormatter();
  const { heightsConverterSave, weightsConverterSave } = useUserMetric();
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (_: React.SyntheticEvent, value: number) => setCurrentTab(value);
  const basicShape = {
    name: Yup.string().required(t_i18n('This field is required')),
    threat_actor_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    first_seen: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_seen: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    sophistication: Yup.object().nullable(),
    resource_level: Yup.object().nullable(),
    roles: Yup.array().nullable(),
    primary_motivation: Yup.object().nullable(),
    secondary_motivations: Yup.array().nullable(),
    personal_motivations: Yup.array().nullable(),
    goals: Yup.string().nullable(),
    date_of_birth: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a date (yyyy-MM-dd)')),
    bornIn: Yup.object().nullable(),
    ethnicity: Yup.object().nullable(),
    gender: Yup.string().nullable().typeError(t_i18n('The value must be a string')),
    marital_status: Yup.string()
      .nullable()
      .typeError(t_i18n('The value must be a string')),
    job_title: Yup.string().max(250, t_i18n('The value is too long')),
    eye_color: Yup.string().nullable(),
    hair_color: Yup.string().nullable(),
    height: Yup.array().of(
      Yup.object().shape({
        measure: Yup.number()
          .min(0)
          .nullable()
          .typeError(t_i18n('The value must be a number')),
        date_seen: Yup.date()
          .nullable()
          .typeError(t_i18n('The value must be a date (yyyy-MM-dd)')),
      }),
    ),
    weight: Yup.array().of(
      Yup.object().shape({
        measure: Yup.number()
          .min(0)
          .nullable()
          .typeError(t_i18n('The value must be a number')),
        date_seen: Yup.date()
          .nullable()
          .typeError(t_i18n('The value must be a date (yyyy-MM-dd)')),
      }),
    ),
  };
  const threatActorIndividualValidator = useSchemaCreationValidation(
    THREAT_ACTOR_INDIVIDUAL_TYPE,
    basicShape,
  );
  const [commit] = useMutation<ThreatActorIndividualCreationMutation>(
    ThreatActorIndividualMutation,
  );

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
      first_seen: values?.first_seen,
      last_seen: values?.last_seen,
      secondary_motivations: (values?.secondary_motivations ?? []).map(
        (v) => v.value,
      ),
      personal_motivations: (values?.personal_motivations ?? []).map(
        (v) => v.value,
      ),
      primary_motivation: values?.primary_motivation?.value,
      roles: (values?.roles ?? []).map(
        (v) => v.value,
      ),
      sophistication: values?.sophistication?.value,
      resource_level: values?.resource_level?.value,
      goals: values?.goals?.split('\n') ?? null,
      bornIn: values?.bornIn?.value,
      ethnicity: values?.ethnicity?.value,
      date_of_birth: values?.date_of_birth,
      gender: values?.gender,
      marital_status: values?.marital_status,
      job_title: values?.job_title,
      eye_color: values?.eye_color,
      hair_color: values?.hair_color,
      height: heightsConverterSave(values?.height ?? []),
      weight: weightsConverterSave(values?.weight ?? []),
    };
    commit({
      variables: { input },
      updater: (store) => {
        if (updater) {
          updater(store, 'threatActorIndividualAdd');
        }
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        MESSAGING$.notifyError(`${error}`);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
        MESSAGING$.notifySuccess(`${t_i18n('entity_Threat-Actor-Individual')} ${t_i18n('successfully created')}`);
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
    first_seen: null,
    last_seen: null,
    secondary_motivations: [],
    personal_motivations: [],
    primary_motivation: null,
    roles: [],
    sophistication: null,
    resource_level: null,
    goals: '',
    file: undefined,
    bornIn: undefined,
    ethnicity: undefined,
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
      {({
        submitForm,
        handleReset,
        isSubmitting,
        setFieldValue,
        values,
        errors,
      }) => (
        <Form>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={handleChangeTab}>
              <Tab
                id="create-overview"
                label={
                  <ErrorBadge
                    badgeContent={Object.keys(errors).length}
                    errors={errors}
                  >
                    {t_i18n('Overview')}
                  </ErrorBadge>
                }
              />
              <Tab id="threat-details" label={t_i18n('Details')} />
              <Tab id="threat-demographics" label={t_i18n('Demographics')} />
              <Tab id="threat-bio" label={t_i18n('Biographics')} />
            </Tabs>
          </Box>
          {currentTab === 0 && (
            <>
              <Field
                component={TextField}
                style={{ marginTop: 20 }}
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
                askAi={true}
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
                label={t_i18n('Threat actor types')}
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
                label={t_i18n('Description')}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
                askAi={true}
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
              <CustomFileUploader setFieldValue={setFieldValue} />
            </>
          )}
          {currentTab === 1 && (
            <>
              <Field
                component={DateTimePickerField}
                name="first_seen"
                textFieldProps={{
                  label: t_i18n('First seen'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <Field
                component={DateTimePickerField}
                name="last_seen"
                textFieldProps={{
                  label: t_i18n('Last seen'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <OpenVocabField
                label={t_i18n('Sophistication')}
                type="threat_actor_individual_sophistication_ov"
                name="sophistication"
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={false}
              />
              <OpenVocabField
                label={t_i18n('Resource level')}
                type="attack-resource-level-ov"
                name="resource_level"
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={false}
              />
              <OpenVocabField
                label={t_i18n('Roles')}
                type="threat-actor-individual-role-ov"
                name="roles"
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={true}
              />
              <OpenVocabField
                label={t_i18n('Primary motivation')}
                type="attack-motivation-ov"
                name="primary_motivation"
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={false}
              />
              <OpenVocabField
                label={t_i18n('Secondary motivations')}
                type="attack-motivation-ov"
                name="secondary_motivations"
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={true}
              />
              <OpenVocabField
                label={t_i18n('Personal motivations')}
                type="attack-motivation-ov"
                name="personal_motivations"
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={true}
              />
              <Field
                component={TextField}
                name="goals"
                label={t_i18n('Goals (1 / line)')}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
              />
            </>
          )}
          {currentTab === 2 && (
            <>
              <CountryField
                id="PlaceOfBirth"
                name="bornIn"
                label={t_i18n('Place of Birth')}
                containerStyle={fieldSpacingContainerStyle}
                onChange={setFieldValue}
              />
              <CountryField
                id="Ethnicity"
                name="ethnicity"
                label={t_i18n('Ethnicity')}
                containerStyle={fieldSpacingContainerStyle}
                onChange={setFieldValue}
              />
              <Field
                id="DateOfBirth"
                component={DateTimePickerField}
                name="date_of_birth"
                onSubmit={setFieldValue}
                textFieldProps={{
                  label: t_i18n('Date of Birth'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <OpenVocabField
                name="marital_status"
                label={t_i18n('Marital Status')}
                type="marital_status_ov"
                variant="edit"
                onChange={setFieldValue}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={[]}
              />
              <OpenVocabField
                name="gender"
                label={t_i18n('Gender')}
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
                label={t_i18n('Job Title')}
                fullWidth={true}
                multiline={false}
                rows="1"
                style={{ marginTop: 20 }}
                onSubmit={setFieldValue}
              />
            </>
          )}
          {currentTab === 3 && (
            <>
              <OpenVocabField
                name="eye_color"
                label={t_i18n('Eye Color')}
                type="eye_color_ov"
                variant="edit"
                onChange={setFieldValue}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={[]}
              />
              <OpenVocabField
                name="hair_color"
                label={t_i18n('Hair Color')}
                type="hair_color_ov"
                variant="edit"
                onChange={setFieldValue}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={[]}
              />
              <HeightFieldAdd
                id="new_height"
                name="height"
                values={values?.height}
                containerStyle={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
              <WeightFieldAdd
                name="weight"
                values={values?.weight}
                containerStyle={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
            </>
          )}
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
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

const ThreatActorIndividualCreation = ({
  paginationOptions,
}: {
  paginationOptions: ThreatActorsIndividualCardsPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_threatActorsIndividuals',
    paginationOptions,
    'threatActorIndividualAdd',
  );
  return (
    <Drawer
      title={t_i18n('Create a threat actor individual')}
      controlledDial={({ onOpen }) => (
        <Button
          className={classes.createBtn}
          color='primary'
          size='small'
          variant='contained'
          onClick={onOpen}
        >
          {t_i18n('Create')} {t_i18n('entity_Threat-Actor-Individual')} <Add />
        </Button>
      )}
    >
      {({ onClose }) => (
        <ThreatActorIndividualCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default ThreatActorIndividualCreation;
