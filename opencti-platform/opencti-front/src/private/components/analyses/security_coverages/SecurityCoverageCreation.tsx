import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import { FormikConfig } from 'formik/dist/types';
import { Box, Card, CardActionArea, CardContent, Typography, Stepper, Step, StepLabel } from '@mui/material';
import { AutoModeOutlined, EditOutlined } from '@mui/icons-material';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { SecurityCoveragesLinesPaginationQuery$variables } from '@components/analyses/__generated__/SecurityCoveragesLinesPaginationQuery.graphql';
import ConfidenceField from '@components/common/form/ConfidenceField';
import PeriodicityField from '../../../../components/fields/PeriodicityField';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm, QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { CoverageInformationFieldAdd } from '../../common/form/CoverageInformationField';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import ListLines from '../../../../components/list_lines/ListLines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import SecurityCoverageEntityLine from './SecurityCoverageEntityLine';
import SwitchField from '../../../../components/fields/SwitchField';
import OpenVocabField from '@components/common/form/OpenVocabField';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';

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
  stepperContainer: {
    marginBottom: 20,
  },
}));

const CARD_WIDTH = 400;
const CARD_HEIGHT = 250;

// Default entity types for coverage
const DEFAULT_ENTITY_TYPES = [
  'Report',
  'Grouping',
  'Case-Incident',
  'Intrusion-Set',
  'Campaign',
  'Incident',
];

// Type definitions for GraphQL responses
interface StixCoreObjectNode {
  id: string;
  name?: string;
  entity_type: string;
  created_at: string;
  representative?: { main: string };
  createdBy?: { id: string; name: string };
  objectLabel?: { id: string; value: string; color: string }[];
  objectMarking?: { id: string; definition_type: string; definition: string; x_opencti_order: number; x_opencti_color: string }[];
}

interface EntitiesQueryProps {
  stixCoreObjects?: {
    edges: Array<{ node: StixCoreObjectNode }>;
  };
}

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

// Query for fetching entities to be covered
const securityCoverageEntitiesQuery = graphql`
  query SecurityCoverageCreationEntitiesQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    stixCoreObjects(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCoreObjects") {
      edges {
        node {
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
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
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
  type_affinity: 'ENDPOINT' | 'CLOUD' | 'WEB' | 'TABLE-TOP';
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
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [commitMutation] = useApiMutation(securityCoverageMutation);

  // Stepper state - if we have a preselected entity, start at step 0 (choose type)
  const [activeStep, setActiveStep] = useState(0);
  const [mode, setMode] = useState<'manual' | 'automated' | null>(null);
  const [selectedEntity, setSelectedEntity] = useState<StixCoreObjectNode | null>(preSelectedEntity);

  // Entity selection state - not persisted to local storage or URL
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState('created_at');
  const [orderAsc, setOrderAsc] = useState(false);
  const initialFilters = {
    ...emptyFilterGroup,
    filters: [
      {
        key: 'regardingOf',
        operator: 'not_eq',
        values: [
          {
            key: 'relationship_type',
            values: [
              'object-covered',
            ],
          },
        ],
        mode: 'or',
      },
    ],
  };

  const [filters, helpers] = useFiltersState(initialFilters);
  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Domain-Object', filters);

  // When we have a preselected entity, we skip the "Select entity" step
  const steps = preSelectedEntityId
    ? [
        t_i18n('Choose type'),
        t_i18n('Coverage details'),
      ]
    : [
        t_i18n('Choose type'),
        t_i18n('Select entity to cover'),
        t_i18n('Coverage details'),
      ];

  const buildColumns = () => {
    return {
      entity_type: {
        label: 'Type',
        width: '12%',
        isSortable: true,
      },
      value: {
        label: 'Value',
        width: '28%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '22%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        width: '16%',
        isSortable: false,
      },
    };
  };

  const handleSelectMode = (newMode: 'manual' | 'automated') => {
    setMode(newMode);
    // If we have a preselected entity, go directly to coverage details (step 1)
    // Otherwise, go to entity selection (step 1)
    setActiveStep(1);
  };

  const handleSelectEntity = (entity: StixCoreObjectNode, setFieldValue?: (field: string, value: unknown) => void) => {
    setSelectedEntity(entity);
    // Update the form name with the selected entity's representative name
    if (setFieldValue && (entity.representative?.main || entity.name)) {
      setFieldValue('name', entity.representative?.main || entity.name);
    }
    // Automatically move to the coverage details step
    setActiveStep(preSelectedEntityId ? 1 : 2);
  };

  // Removed handleBack - users should click on stepper steps directly

  const handleClose = () => {
    // Reset all state when closing drawer
    setActiveStep(0);
    setMode(null);
    setSelectedEntity(null);
    helpers.handleClearAllFilters();
    if (onClose) {
      onClose();
    }
  };

  const onSubmit: FormikConfig<SecurityCoverageFormValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    if (!selectedEntity) {
      setSubmitting(false);
      return;
    }
    const finalValues = {
      name: values.name,
      description: values.description,
      objectCovered: selectedEntity.id,
      ...(mode === 'manual' ? {
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
      confidence: values.confidence,
    };

    commitMutation({
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
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
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
      auto_enrichment_disable: mode === 'manual',
      objectLabel: defaultLabels,
      coverage_information: [],
      periodicity: 'P1D',
      duration: 'P30D',
      type_affinity: 'ENDPOINT',
      platforms_affinity: ['windows', 'linux', 'macos'],
    },
  );

  const renderStepContent = (
    step: number,
    values: SecurityCoverageFormValues,
    setFieldValue: (field: string, value: unknown) => void,
    isSubmitting: boolean,
    _submitForm: () => void,
    _resetForm: () => void,
  ) => {
    // If we have a preselected entity, we only have 2 steps (type selection and coverage details)
    // Map step 0 -> 0 (Choose type), step 1 -> 2 (Coverage details)
    let actualStep = step;
    if (preSelectedEntityId) {
      actualStep = step === 1 ? 2 : step;
    }

    switch (actualStep) {
      case 0:
        // Step 1: Choose Type (Manual or Automated)
        return (
          <Box>
            <Box
              sx={{
                display: 'flex',
                gap: 4,
                justifyContent: 'center',
                alignItems: 'center',
                minHeight: '40vh',
                flexWrap: 'wrap',
                marginTop: 4,
              }}
            >
              <Card
                variant="outlined"
                style={{
                  width: CARD_WIDTH,
                  height: CARD_HEIGHT,
                  textAlign: 'center',
                }}
              >
                <CardActionArea
                  onClick={() => handleSelectMode('manual')}
                  sx={{
                    height: '100%',
                    '&:hover': {
                      backgroundColor: 'action.hover',
                    },
                  }}
                  aria-label={t_i18n('Manual Input')}
                >
                  <CardContent>
                    <EditOutlined sx={{ fontSize: 40 }} color="primary" />
                    <Typography
                      gutterBottom
                      variant="h2"
                      style={{ marginTop: 20 }}
                    >
                      {t_i18n('Manual Input')}
                    </Typography>
                    <br />
                    <Typography variant="body1">
                      {t_i18n('Manually enter security coverage metrics and scores for this entity')}
                    </Typography>
                  </CardContent>
                </CardActionArea>
              </Card>

              <Card
                variant="outlined"
                style={{
                  width: CARD_WIDTH,
                  height: CARD_HEIGHT,
                  textAlign: 'center',
                  opacity: hasEnrichmentConnectors ? 1 : 0.5,
                }}
              >
                <CardActionArea
                  onClick={() => hasEnrichmentConnectors && handleSelectMode('automated')}
                  disabled={!hasEnrichmentConnectors}
                  sx={{
                    height: '100%',
                    '&:hover': hasEnrichmentConnectors ? {
                      backgroundColor: 'action.hover',
                    } : {},
                  }}
                  aria-label={t_i18n('Automated using enrichment')}
                >
                  <CardContent>
                    <AutoModeOutlined sx={{ fontSize: 40 }} color={hasEnrichmentConnectors ? 'primary' : 'disabled'} />
                    <Typography
                      gutterBottom
                      variant="h2"
                      style={{ marginTop: 20 }}
                      color={hasEnrichmentConnectors ? 'textPrimary' : 'textSecondary'}
                    >
                      {t_i18n('Automated using enrichment')}
                    </Typography>
                    <br />
                    <Typography
                      variant="body1"
                      color={hasEnrichmentConnectors ? 'textPrimary' : 'textSecondary'}
                    >
                      {hasEnrichmentConnectors
                        ? t_i18n('OpenAEV (or other AEV platforms) can be used to automate security coverage assessment')
                        : t_i18n('No enrichment connector available for Security Coverage')}
                    </Typography>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Box>
            <div className={classes.buttons} style={{ marginTop: 20 }}>
              <Button
                onClick={handleClose}
                classes={{ root: classes.button }}
              >
                {t_i18n('Cancel')}
              </Button>
            </div>
          </Box>
        );

      case 1: {
        // Step 2: Select Entity to Cover
        const queryPaginationOptions = {
          types: DEFAULT_ENTITY_TYPES,
          search: searchTerm,
          filters: contextFilters,
          orderBy: sortBy,
          orderMode: orderAsc ? 'asc' : 'desc' as 'asc' | 'desc',
          count: 50,
          cursor: null,
        };

        const handleSort = (field: string, order: boolean) => {
          setSortBy(field);
          setOrderAsc(order);
        };
        const handleSearch = (value: string) => {
          setSearchTerm(value);
        };

        return (
          <>
            <ListLines
              helpers={helpers}
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={buildColumns()}
              handleSort={handleSort}
              handleSearch={handleSearch}
              handleAddFilter={helpers.handleAddSingleValueFilter}
              handleRemoveFilter={helpers.handleRemoveRepresentationFilter}
              handleSwitchFilter={helpers.handleSwitchGlobalMode}
              handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
              handleSwitchLocalMode={helpers.handleSwitchLocalMode}
              keyword={searchTerm}
              filters={filters}
              paginationOptions={queryPaginationOptions}
              numberOfElements={{ number: 0, symbol: '' }}
              availableFilterKeys={['entity_type', 'objectLabel', 'createdBy', 'objectMarking', 'created_start_date', 'created_end_date', 'created_at_start_date', 'created_at_end_date']}
              availableEntityTypes={DEFAULT_ENTITY_TYPES}
              noPadding={true}
              disableCards={true}
              noHeaders={false}
            >
              <QueryRenderer
                query={securityCoverageEntitiesQuery}
                variables={queryPaginationOptions}
                render={(renderProps: { props: EntitiesQueryProps | null }) => {
                  const { props } = renderProps;
                  if (!props || !props.stixCoreObjects) {
                    return <Loader variant={LoaderVariant.inElement} />;
                  }
                  return (
                    <ListLinesContent
                      initialLoading={false}
                      loadMore={() => {}}
                      hasMore={() => false}
                      isLoading={() => false}
                      dataList={props.stixCoreObjects.edges.slice(0, 50)}
                      globalCount={Math.min(props.stixCoreObjects.edges.length, 50)}
                      LineComponent={SecurityCoverageEntityLine}
                      DummyLineComponent={() => null}
                      dataColumns={buildColumns()}
                      paginationOptions={queryPaginationOptions}
                      selectedElements={{}}
                      selectAll={false}
                      onToggleEntity={(entity: StixCoreObjectNode) => handleSelectEntity(entity, setFieldValue)}
                      onLabelClick={helpers.handleAddSingleValueFilter}
                      redirectionMode={undefined}
                      selectedEntity={selectedEntity}
                    />
                  );
                }}
              />
            </ListLines>
          </>
        );
      }

      case 2:
        // Step 3: Coverage Details Form
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
            />
            <ConfidenceField
              containerStyle={fieldSpacingContainerStyle}
              entityType="Security-Coverage"
            />
            <PeriodicityField
              name="periodicity"
              label={mode === 'automated' ? t_i18n('Coverage recurrence (every x)') : t_i18n('Coverage validity period')}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            {mode === 'automated' && (
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
                  <MenuItem key="CLOUD" value="CLOUD">
                    {t_i18n('Cloud')}
                  </MenuItem>
                  <MenuItem key="WEB" value="WEB">
                    {t_i18n('Web')}
                  </MenuItem>
                  <MenuItem key="TABLE-TOP" value="TABLE-TOP">
                    {t_i18n('Table-top')}
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
            {mode === 'manual' && (
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
            <div className={classes.buttons}>
              <Button
                variant="secondary"
                onClick={handleClose}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                type="submit"
                disabled={isSubmitting || !values.name || (mode === 'manual' && (!values.coverage_information || values.coverage_information.length === 0))}
                classes={{ root: classes.button }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          </Box>
        );

      default:
        return null;
    }
  };

  return (
    <Box>
      <div className={classes.stepperContainer}>
        <Stepper activeStep={activeStep}>
          {steps.map((label, index) => (
            <Step key={label}>
              <StepLabel
                onClick={() => {
                  if (index < activeStep) {
                    setActiveStep(index);
                  }
                }}
                style={{ cursor: index < activeStep ? 'pointer' : 'default' }}
              >
                {label}
              </StepLabel>
            </Step>
          ))}
        </Stepper>
      </div>

      <Formik<SecurityCoverageFormValues>
        enableReinitialize
        initialValues={initialValues}
        validationSchema={securityCoverageValidation(t_i18n, mode === 'automated')}
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

          return <SecurityCoverageCreationFormInner {...props} preSelectedEntity={queryProps.stixCoreObject} />;
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
