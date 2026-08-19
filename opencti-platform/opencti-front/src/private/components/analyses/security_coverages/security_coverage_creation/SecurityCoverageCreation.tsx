import Button from '@common/button/Button';
import { SecurityCoveragesLinesPaginationQuery$variables } from '@components/analyses/__generated__/SecurityCoveragesLinesPaginationQuery.graphql';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import ConfidenceField from '@components/common/form/ConfidenceField';
import OpenVocabField from '@components/common/form/OpenVocabField';
import { Box, Step, StepLabel, Stepper } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import FormButtonContainer from '../../../../../components/common/form/FormButtonContainer';
import CreateEntityControlledDial from '../../../../../components/CreateEntityControlledDial';
import MarkdownField from '../../../../../components/fields/markdownField/MarkdownField';
import PeriodicityField from '../../../../../components/fields/PeriodicityField';
import SelectField from '../../../../../components/fields/SelectField';
import SwitchField from '../../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import TextField from '../../../../../components/TextField';
import { handleErrorInForm, QueryRenderer } from '../../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useDefaultValues from '../../../../../utils/hooks/useDefaultValues';
import useMarkdownCreationFilesInput from '../../../../../utils/markdown/useMarkdownCreationFilesInput';
import { insertNode } from '../../../../../utils/store';
import { CoverageInformationFieldAdd } from '../../../common/form/CoverageInformationField';
import CreatedByField from '../../../common/form/CreatedByField';
import ObjectLabelField from '../../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../../common/form/ObjectMarkingField';
import { useNavigate } from 'react-router-dom';
import { SecurityCoverageCreationMutation } from './__generated__/SecurityCoverageCreationMutation.graphql';
import ChooseModeStep from './ChooseModeStep';
import SelectCoveredEntityStep from './SelectCoveredEntityStep';
import { SecurityCoverageMode, StepKey, StixCoreObjectNode } from './securityCoverageCreation-types';

interface ConnectorsQueryProps {
  connectors?: Array<{
    active: boolean;
    connector_type?: string;
    connector_scope?: string[];
  }>;
}

const securityCoverageMutation = graphql`
  mutation SecurityCoverageCreationMutation($input: SecurityCoverageAddInput!) {
    securityCoverageAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      auto_enrichment_disable
      coverage_information {
        coverage_name
        coverage_score
      }
      ...SecurityCoveragesLine_node
    }
  }
`;

// Query for checking enrichment connectors availability
const securityCoverageConnectorsQuery = graphql`
  query SecurityCoverageCreationConnectorsQuery {
    connectors {
      id
      name
      active
      connector_type
      connector_scope
    }
  }
`;

const securityCoverageValidation = (t: (value: string) => string, isAutomated: boolean) => {
  const baseShape = {
    name: Yup.string().required(t('This field is required')),
    description: Yup.string().nullable(),
    external_uri: Yup.string().url().nullable(),
  };

  if (isAutomated) {
    return Yup.object().shape({
      ...baseShape,
      periodicity: Yup.string().required(t('This field is required')),
      duration: Yup.string().required(t('This field is required')),
      type_affinity: Yup.string().required(t('This field is required')),
      platforms_affinity: Yup.array().min(1, t('At least one platform affinity is required')),
    });
  }

  return Yup.object().shape({
    ...baseShape,
    coverage_information: Yup.array().of(
      Yup.object().shape({
        coverage_name: Yup.string().required(t('This field is required')),
        coverage_score: Yup.number()
          .required(t('This field is required'))
          .min(0, t('Score must be at least 0'))
          .max(100, t('Score must be at most 100')),
      }),
    ).min(1, t('At least one coverage metric is required')),
  });
};

export interface SecurityCoverageFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onClose?: () => void;
  inputValue?: string;
  defaultCreatedBy?: FieldOption;
  defaultMarkingDefinitions?: FieldOption[];
  defaultConfidence?: number;
  hasEnrichmentConnectors?: boolean;
  preSelectedEntityId?: string;
  preSelectedEntityName?: string;
}

interface SecurityCoverageFormValues {
  name: string;
  description: string;
  external_uri: string;
  auto_enrichment_disable: boolean;
  confidence: number | undefined;
  createdBy?: FieldOption;
  objectMarking: { value: string }[];
  objectLabel: { value: string; label: string }[];
  coverage_information: { coverage_name: string; coverage_score: number | string }[];
  periodicity?: string;
  duration?: string;
  type_affinity: 'ENDPOINT';
  platforms_affinity: string[];
}

// Query for fetching a single entity when preselected
const securityCoveragePreselectedEntityQuery = graphql`
  query SecurityCoverageCreationPreselectedEntityQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      standard_id
      entity_type
      created_at
      representative {
        main
      }
      createdBy {
        ... on Identity {
          id
          name
        }
      }
      creators {
        id
        name
      }
      objectLabel {
        id
        value
        color
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
    }
  }
`;

interface SecurityCoverageFormInnerProps extends SecurityCoverageFormProps {
  preSelectedEntity: StixCoreObjectNode | null;
  shouldRedirect?: boolean;
}

const SecurityCoverageCreationFormInner: FunctionComponent<SecurityCoverageFormInnerProps> = ({
  updater,
  onClose,
  inputValue,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  hasEnrichmentConnectors = false,
  preSelectedEntityId,
  preSelectedEntityName,
  preSelectedEntity,
  shouldRedirect,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();

  // Stepper state - if we have a preselected entity, start at step 0 (choose type)
  const [activeStep, setActiveStep] = useState<StepKey>(StepKey.MODE);
  const [mode, setMode] = useState<SecurityCoverageMode | null>(null);
  const [selectedEntity, setSelectedEntity] = useState<StixCoreObjectNode | null>(preSelectedEntity);

  // When we have a preselected entity, we skip the "Select entity" step
  const steps = [
    { title: t_i18n('Choose type'), step: StepKey.MODE },
    ...(preSelectedEntityId ? [] : [{ title: t_i18n('Select entity to cover'), step: StepKey.OBJECT_COVERED }]),
    ...(mode === SecurityCoverageMode.MANUAL ? [{ title: t_i18n('Select object covered entities'), step: StepKey.COMPATIBLE_ENTITIES }] : []),
    { title: t_i18n('Coverage details'), step: StepKey.COVERAGE_DETAILS },
  ];

  const activeStepIndex = Math.max(0, steps.findIndex(({ step }) => step === activeStep));

  const handleSelectMode = (newMode: SecurityCoverageMode) => {
    setMode(newMode);
    // If no preselected entity, go to entity selection (step object covered)
    // If we have a preselected entity :
    // option 1 : manual mode : go directly to covered entities selection
    // option 2 : automated mode : go directly to coverage details
    if (!preSelectedEntityId) {
      setActiveStep(StepKey.OBJECT_COVERED);
    } else {
      setActiveStep(newMode === SecurityCoverageMode.MANUAL ? StepKey.COMPATIBLE_ENTITIES : StepKey.COVERAGE_DETAILS);
    }
  };

  const handleSelectEntity = (entity: StixCoreObjectNode, setFieldValue: (field: string, value: unknown) => void) => {
    setSelectedEntity(entity);
    // Update the form name with the selected entity's representative name
    if (entity.representative?.main || entity.name) {
      setFieldValue('name', entity.representative?.main || entity.name);
    }
    // Automatically move to the select covered entities step (if manual mode) or coverage details otherwise
    setActiveStep(mode === SecurityCoverageMode.MANUAL ? StepKey.COMPATIBLE_ENTITIES : StepKey.COVERAGE_DETAILS);
  };

  // Removed handleBack - users should click on stepper steps directly

  const handleClose = () => {
    // Reset all state when closing drawer
    setActiveStep(StepKey.MODE);
    setMode(null);
    setSelectedEntity(null);
    if (onClose) {
      onClose();
    }
  };

  const [commit] = useApiMutation<SecurityCoverageCreationMutation>(
    securityCoverageMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Security-Coverage')} ${t_i18n('successfully created')}` },
  );

  const { buildCreationFilesInput, registerMarkdownImagesController } = useMarkdownCreationFilesInput();

  const onSubmit: FormikConfig<SecurityCoverageFormValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    if (!selectedEntity) {
      setSubmitting(false);
      return;
    }
    const finalValues = {
      ...buildCreationFilesInput(),
      name: values.name,
      description: values.description,
      objectCovered: selectedEntity.id,
      ...(mode === SecurityCoverageMode.MANUAL ? {
        coverage_information: values.coverage_information.map((info) => ({
          coverage_name: info.coverage_name,
          coverage_score: Number(info.coverage_score),
        })),
      } : {}),
      periodicity: values.periodicity,
      duration: values.duration,
      type_affinity: values.type_affinity,
      platforms_affinity: values.platforms_affinity,
      external_uri: values.external_uri,
      auto_enrichment_disable: values.auto_enrichment_disable,
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      confidence: parseInt(String(values.confidence), 10),
      add_related_entities: mode === SecurityCoverageMode.MANUAL,
    };

    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'securityCoverageAdd');
        }
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        handleClose();
        if (response.securityCoverageAdd && shouldRedirect) {
          navigate(`/dashboard/analyses/security_coverages/${response.securityCoverageAdd.id}`);
        }
      },
    });
  };

  // Use entity name from preselected entity or fallback to provided name
  const defaultName = preSelectedEntity?.representative?.main || preSelectedEntity?.name || preSelectedEntityName || inputValue || '';
  const defaultLabels = (preSelectedEntity?.objectLabel ?? []).map((label) => ({ value: label.id, label: label.value }));

  const initialValues = useDefaultValues<SecurityCoverageFormValues>(
    'Security-Coverage',
    {
      name: defaultName,
      description: '',
      external_uri: '',
      createdBy: defaultCreatedBy,
      objectMarking: defaultMarkingDefinitions ?? [],
      confidence: defaultConfidence,
      auto_enrichment_disable: mode === SecurityCoverageMode.MANUAL,
      objectLabel: defaultLabels,
      coverage_information: [],
      periodicity: 'P1D',
      duration: 'P30D',
      type_affinity: 'ENDPOINT',
      platforms_affinity: ['windows', 'linux', 'macos'],
    },
  );

  const renderStepContent = (
    step: StepKey,
    values: SecurityCoverageFormValues,
    setFieldValue: (field: string, value: unknown) => void,
    isSubmitting: boolean,
    _submitForm: () => void,
    _resetForm: () => void,
  ) => {
    switch (step) {
      case StepKey.MODE:
      // Choose Type (all cases)
        return (
          <ChooseModeStep
            hasEnrichmentConnectors={hasEnrichmentConnectors}
            onSelectMode={handleSelectMode}
            onClose={handleClose}
          />
        );

      case StepKey.OBJECT_COVERED:
        // Select Entity to Cover (when creation from security coverage view, either manual or automated case)
        return (
          <SelectCoveredEntityStep
            onSelectEntity={(entity) => handleSelectEntity(entity, setFieldValue)}
            selectedEntity={selectedEntity}
          />
        );

      case StepKey.COMPATIBLE_ENTITIES:
        // Select covered entities (manual mode)
        return <></>;

      case StepKey.COVERAGE_DETAILS:
        // Coverage Details Form (all cases)
        return (
          <Box>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              required
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows={4}
              style={fieldSpacingContainerStyle}
              autoPersistOnBlur={false}
              registerMarkdownImagesController={registerMarkdownImagesController}
              uploadFileMarkings={values.objectMarking.map((v) => v.value)}
            />
            <ConfidenceField
              containerStyle={fieldSpacingContainerStyle}
              entityType="Security-Coverage"
            />
            <PeriodicityField
              name="periodicity"
              label={mode === SecurityCoverageMode.AUTO ? t_i18n('Coverage recurrence (every x)') : t_i18n('Coverage validity period')}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            {mode === SecurityCoverageMode.AUTO && (
              <>
                <PeriodicityField
                  name="duration"
                  label={t_i18n('Duration')}
                  style={fieldSpacingContainerStyle}
                  setFieldValue={setFieldValue}
                />
                <Field
                  component={SelectField}
                  variant="standard"
                  name="type_affinity"
                  onChange={(name: string, value: string) => setFieldValue(name, value)}
                  label={t_i18n('Type affinity')}
                  fullWidth={true}
                  containerstyle={{ width: '100%', marginTop: 20 }}
                >
                  <MenuItem key="ENDPOINT" value="ENDPOINT">
                    {t_i18n('Endpoint')}
                  </MenuItem>
                </Field>
                <OpenVocabField
                  label={t_i18n('Platform(s) affinity')}
                  type="platforms_ov"
                  name="platforms_affinity"
                  onChange={(name, value) => setFieldValue(name, value)}
                  containerStyle={fieldSpacingContainerStyle}
                  multiple={true}
                />
              </>
            )}
            <Field
              component={SwitchField}
              type="checkbox"
              disabled={true}
              name="auto_enrichment_disable"
              label={t_i18n('Force manual coverage (prevent enrichment connectors from running)')}
              containerstyle={fieldSpacingContainerStyle}
            />
            {mode === SecurityCoverageMode.MANUAL && (
              <>
                <CoverageInformationFieldAdd
                  name="coverage_information"
                  values={values.coverage_information}
                  setFieldValue={setFieldValue}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="external_uri"
                  label={t_i18n('Source external link')}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
              </>
            )}
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
              setFieldValue={setFieldValue}
            />
            <FormButtonContainer>
              <Button
                variant="secondary"
                onClick={handleClose}
                disabled={isSubmitting}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                type="submit"
                disabled={isSubmitting || !values.name || (mode === SecurityCoverageMode.MANUAL && (!values.coverage_information || values.coverage_information.length === 0))}
              >
                {t_i18n('Create')}
              </Button>
            </FormButtonContainer>
          </Box>
        );

      default:
        return null;
    }
  };

  return (
    <Box>
      <Box sx={{ marginBottom: 2.5 }}>
        <Stepper activeStep={activeStepIndex}>
          {steps.map(({ title, step }, index) => (
            <Step key={step}>
              <StepLabel
                onClick={() => {
                  if (index < activeStepIndex) {
                    setActiveStep(step);
                  }
                }}
                style={{ cursor: index < activeStepIndex ? 'pointer' : 'default' }}
              >
                {title}
              </StepLabel>
            </Step>
          ))}
        </Stepper>
      </Box>

      <Formik<SecurityCoverageFormValues>
        enableReinitialize
        initialValues={initialValues}
        validationSchema={securityCoverageValidation(t_i18n, mode === SecurityCoverageMode.AUTO)}
        onSubmit={onSubmit}
      >
        {({ values, isSubmitting, setFieldValue, resetForm, submitForm }) => (
          <Form>
            {renderStepContent(activeStep, values, setFieldValue, isSubmitting, submitForm, resetForm)}
          </Form>
        )}
      </Formik>
    </Box>
  );
};

interface SecurityCoverageCreationProps {
  paginationOptions: SecurityCoveragesLinesPaginationQuery$variables;
}

// Wrapper component to handle preselected entity fetching
export const SecurityCoverageCreationForm: FunctionComponent<SecurityCoverageFormProps> = (props) => {
  const { preSelectedEntityId } = props;

  if (preSelectedEntityId) {
    return (
      <QueryRenderer
        query={securityCoveragePreselectedEntityQuery}
        variables={{ id: preSelectedEntityId }}
        render={({ props: queryProps }: { props: { stixCoreObject: StixCoreObjectNode | null } | null }) => {
          if (!queryProps || !queryProps.stixCoreObject) {
            return <Loader variant={LoaderVariant.inElement} />;
          }

          return <SecurityCoverageCreationFormInner {...props} preSelectedEntity={queryProps.stixCoreObject} shouldRedirect={true} />;
        }}
      />
    );
  }

  return <SecurityCoverageCreationFormInner {...props} preSelectedEntity={null} />;
};

const SecurityCoverageCreationWrapper: FunctionComponent<{ updater: (store: RecordSourceSelectorProxy, key: string) => void; onClose?: () => void }> = ({ updater, onClose }) => {
  return (
    <QueryRenderer
      query={securityCoverageConnectorsQuery}
      variables={{}}
      render={({ props }: { props: ConnectorsQueryProps | null }) => {
        const connectors = props?.connectors || [];
        const hasConnector = connectors.some((connector) => {
          return connector.active
            && connector.connector_type === 'INTERNAL_ENRICHMENT'
            && connector.connector_scope
            && connector.connector_scope.some((scope: string) => scope.toLowerCase() === 'security-coverage');
        });
        return <SecurityCoverageCreationForm updater={updater} onClose={onClose} hasEnrichmentConnectors={hasConnector} />;
      }}
    />
  );
};

const SecurityCoverageCreation: FunctionComponent<SecurityCoverageCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination__securityCoverages',
    paginationOptions,
    'securityCoverageAdd',
    null,
    null,
    null,
    null,
  );

  const CreateSecurityCoverageControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Security-Coverage" {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a security coverage')}
      controlledDial={CreateSecurityCoverageControlledDial}
    >
      {({ onClose }) => <SecurityCoverageCreationWrapper updater={updater} onClose={onClose} />}
    </Drawer>
  );
};

export default SecurityCoverageCreation;
