import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik, FormikErrors } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { styled } from '@mui/material/styles';
import { Badge, BadgeProps } from '@mui/material';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import CountryField from '@components/common/form/CountryField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { insertNode } from '../../../../utils/store';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
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
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import { splitMultilines } from '../../../../utils/String';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

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
      representative {
        main
      }
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
  confidence: number | null;
  description: string;
  createdBy: FieldOption | null;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  first_seen: Date | null;
  last_seen: Date | null;
  goals: string | null;
  sophistication: FieldOption | null;
  resource_level: FieldOption | null;
  roles: FieldOption[] | null;
  primary_motivation: FieldOption | null;
  secondary_motivations: FieldOption[] | null;
  personal_motivations: FieldOption[] | null;
  file: File | null;
  bornIn: FieldOption | undefined;
  ethnicity: FieldOption | undefined;
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
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
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
  bulkModalOpen = false,
  onBulkModalClose,
}) => {
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const { heightsConverterSave, weightsConverterSave } = useUserMetric();
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (_: React.SyntheticEvent, value: number) => setCurrentTab(value);
  const { mandatoryAttributes } = useIsMandatoryAttribute(THREAT_ACTOR_INDIVIDUAL_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string(),
    threat_actor_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    objectMarking: Yup.array().nullable(),
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
  }, mandatoryAttributes);
  const threatActorIndividualValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
  );

  const [commit] = useApiMutation<ThreatActorIndividualCreationMutation>(
    ThreatActorIndividualMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Threat-Actor-Individual')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<ThreatActorIndividualCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'threatActorIndividualAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<ThreatActorIndividualAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const allNames = splitMultilines(values.name);
    const variables: ThreatActorIndividualCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
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
      },
    }));

    bulkCommit({
      variables,
      onStepError: (error) => {
        handleErrorInForm(error, setErrors);
      },
      onCompleted: (total: number) => {
        setSubmitting(false);
        if (total < 2) {
          resetForm();
          onCompleted?.();
        }
      },
    });
  };

  const initialValues = useDefaultValues(THREAT_ACTOR_INDIVIDUAL_TYPE, {
    name: inputValue ?? '',
    threat_actor_types: [],
    confidence: defaultConfidence ?? null,
    description: '',
    createdBy: defaultCreatedBy ?? null,
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
    file: null,
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
    <Formik<ThreatActorIndividualAddInput>
      initialValues={initialValues}
      validationSchema={threatActorIndividualValidator}
      validateOnChange={true}
      validateOnBlur={true}
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
        resetForm,
      }) => (
        <>
          <Form>
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tabs value={currentTab} onChange={handleChangeTab}>
                <Tab
                  id="create-overview"
                  label={(
                    <ErrorBadge
                      badgeContent={Object.keys(errors).length}
                    >
                      {t_i18n('Overview')}
                    </ErrorBadge>
                  )}
                />
                <Tab id="threat-details" label={t_i18n('Details')} />
                <Tab id="threat-demographics" label={t_i18n('Demographics')} />
                <Tab id="threat-bio" label={t_i18n('Biographics')} />
              </Tabs>
            </Box>
            {currentTab === 0 && (
              <>
                <BulkTextModal
                  open={bulkModalOpen}
                  onClose={onBulkModalClose}
                  onValidate={async (val) => {
                    await setFieldValue('name', val);
                    if (splitMultilines(val).length > 1) {
                      await setFieldValue('file', null);
                    }
                  }}
                  formValue={values.name}
                />
                <ProgressBar
                  open={progressBarOpen}
                  value={(bulkCurrentCount / bulkCount) * 100}
                  label={`${bulkCurrentCount}/${bulkCount}`}
                  title={t_i18n('Create multiple entities')}
                  onClose={() => {
                    setProgressBarOpen(false);
                    resetForm();
                    resetBulk();
                    onCompleted?.();
                  }}
                >
                  <BulkResult variablesToString={(v) => v.input.name} />
                </ProgressBar>
                <Field
                  component={BulkTextField}
                  style={{ marginTop: 20 }}
                  name="name"
                  label={t_i18n('Name')}
                  required={(mandatoryAttributes.includes('name'))}
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
                  required={(mandatoryAttributes.includes('threat_actor_types'))}
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
                  required={(mandatoryAttributes.includes('description'))}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 20 }}
                  askAi={true}
                />
                <CreatedByField
                  name="createdBy"
                  required={(mandatoryAttributes.includes('createdBy'))}
                  style={fieldSpacingContainerStyle}
                  setFieldValue={setFieldValue}
                />
                <ObjectLabelField
                  name="objectLabel"
                  required={(mandatoryAttributes.includes('objectLabel'))}
                  style={fieldSpacingContainerStyle}
                  setFieldValue={setFieldValue}
                  values={values.objectLabel}
                />
                <ObjectMarkingField
                  name="objectMarking"
                  required={(mandatoryAttributes.includes('objectMarking'))}
                  style={fieldSpacingContainerStyle}
                  setFieldValue={setFieldValue}
                />
                <ExternalReferencesField
                  name="externalReferences"
                  required={(mandatoryAttributes.includes('externalReferences'))}
                  style={fieldSpacingContainerStyle}
                  setFieldValue={setFieldValue}
                  values={values.externalReferences}
                />
                <Field
                  component={CustomFileUploader}
                  name="file"
                  setFieldValue={setFieldValue}
                  disabled={splitMultilines(values.name).length > 1}
                  noFileSelectedLabel={splitMultilines(values.name).length > 1
                    ? t_i18n('File upload not allowed in bulk creation')
                    : undefined
                  }
                />
              </>
            )}
            {currentTab === 1 && (
              <>
                <Field
                  component={DateTimePickerField}
                  name="first_seen"
                  required={(mandatoryAttributes.includes('first_seen'))}
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
                  required={(mandatoryAttributes.includes('last_seen'))}
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
                  required={(mandatoryAttributes.includes('sophistication'))}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={false}
                />
                <OpenVocabField
                  label={t_i18n('Resource level')}
                  type="attack-resource-level-ov"
                  name="resource_level"
                  required={(mandatoryAttributes.includes('resource_level'))}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={false}
                />
                <OpenVocabField
                  label={t_i18n('Roles')}
                  type="threat-actor-individual-role-ov"
                  name="roles"
                  required={(mandatoryAttributes.includes('roles'))}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={true}
                />
                <OpenVocabField
                  label={t_i18n('Primary motivation')}
                  type="attack-motivation-ov"
                  name="primary_motivation"
                  required={(mandatoryAttributes.includes('primary_motivation'))}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={false}
                />
                <OpenVocabField
                  label={t_i18n('Secondary motivations')}
                  type="attack-motivation-ov"
                  name="secondary_motivations"
                  required={(mandatoryAttributes.includes('secondary_motivations'))}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={true}
                />
                <OpenVocabField
                  label={t_i18n('Personal motivations')}
                  type="attack-motivation-ov"
                  name="personal_motivations"
                  required={(mandatoryAttributes.includes('personal_motivations'))}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={true}
                />
                <Field
                  component={TextField}
                  name="goals"
                  label={t_i18n('Goals (1 / line)')}
                  required={(mandatoryAttributes.includes('goals'))}
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
                  required={(mandatoryAttributes.includes('bornIn'))}
                  containerStyle={fieldSpacingContainerStyle}
                  onChange={setFieldValue}
                />
                <CountryField
                  id="Ethnicity"
                  name="ethnicity"
                  label={t_i18n('Ethnicity')}
                  required={(mandatoryAttributes.includes('ethnicity'))}
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
                  required={(mandatoryAttributes.includes('marital_status'))}
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
                  required={(mandatoryAttributes.includes('gender'))}
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
                  required={(mandatoryAttributes.includes('job_title'))}
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
                  required={(mandatoryAttributes.includes('eye_color'))}
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
                  required={(mandatoryAttributes.includes('hair_color'))}
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
            <div style={{
              marginTop: '20px',
              textAlign: 'right',
            }}
            >
              <Button
                variant="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
                sx={{ marginLeft: 2 }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
                sx={{ marginLeft: 2 }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          </Form>
        </>
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
  const [bulkOpen, setBulkOpen] = useState(false);

  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_threatActorsIndividuals',
    paginationOptions,
    'threatActorIndividualAdd',
  );

  const CreateThreatActorIndividualControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Threat-Actor-Individual" {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a threat actor individual')}
      controlledDial={CreateThreatActorIndividualControlledDial}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
    >
      {({ onClose }) => (
        <ThreatActorIndividualCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
        />
      )}
    </Drawer>
  );
};

export default ThreatActorIndividualCreation;
