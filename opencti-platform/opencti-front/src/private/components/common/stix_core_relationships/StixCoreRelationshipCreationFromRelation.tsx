import React, { FunctionComponent, ReactElement, ReactNode, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { FormikConfig } from 'formik';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as R from 'ramda';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { Add, ChevronRightOutlined } from '@mui/icons-material';
import { Stack } from '@mui/material';
import { commitMutation, handleErrorInForm } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps, DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { formatDate } from '../../../../utils/Time';
import { insertNode } from '../../../../utils/store';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { UseLocalStorageHelpers, usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { LocalStorage } from '../../../../utils/hooks/useLocalStorageModel';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import {
  StixCoreRelationshipCreationFromEntityForm,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
} from './StixCoreRelationshipCreationFromEntity';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables,
} from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import { StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data } from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data.graphql';
import { StixCoreRelationshipCreationFromEntityStixCoreObjectsLine_node$data } from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLine_node.graphql';
import {
  StixCoreRelationshipCreationFromRelationQuery,
  StixCoreRelationshipCreationFromRelationQuery$data,
} from './__generated__/StixCoreRelationshipCreationFromRelationQuery.graphql';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import useAuth, { UserContext } from '../../../../utils/hooks/useAuth';
import Drawer from '../drawer/Drawer';

const stixCoreRelationshipCreationFromRelationQuery = graphql`
  query StixCoreRelationshipCreationFromRelationQuery($id: String!) {
    stixCoreRelationship(id: $id) {
      id
      entity_type
      parent_types
      relationship_type
      description
      from {
        ... on BasicObject {
          id
          entity_type
        }
        ... on BasicRelationship {
          id
          entity_type
        }
        ... on AttackPattern {
          name
        }
        ... on Campaign {
          name
        }
        ... on CourseOfAction {
          name
        }
        ... on Individual {
          name
        }
        ... on Organization {
          name
        }
        ... on Sector {
          name
        }
        ... on System {
          name
        }
        ... on Indicator {
          name
        }
        ... on Infrastructure {
          name
        }
        ... on IntrusionSet {
          name
        }
        ... on Position {
          name
        }
        ... on City {
          name
        }
        ... on AdministrativeArea {
          name
        }
        ... on Country {
          name
        }
        ... on Region {
          name
        }
        ... on Malware {
          name
        }
        ... on MalwareAnalysis {
          result_name
        }
        ... on DataComponent {
          name
        }
        ... on DataSource {
          name
        }
        ... on ThreatActor {
          name
        }
        ... on Tool {
          name
        }
        ... on Vulnerability {
          name
        }
        ... on Incident {
          name
        }
        ... on StixCyberObservable {
          observable_value
        }
      }
      to {
        ... on BasicObject {
          id
          entity_type
        }
        ... on BasicRelationship {
          id
          entity_type
        }
        ... on AttackPattern {
          name
        }
        ... on Campaign {
          name
        }
        ... on CourseOfAction {
          name
        }
        ... on Individual {
          name
        }
        ... on Organization {
          name
        }
        ... on Sector {
          name
        }
        ... on System {
          name
        }
        ... on Indicator {
          name
        }
        ... on Infrastructure {
          name
        }
        ... on IntrusionSet {
          name
        }
        ... on Position {
          name
        }
        ... on City {
          name
        }
        ... on AdministrativeArea {
          name
        }
        ... on Country {
          name
        }
        ... on Region {
          name
        }
        ... on Malware {
          name
        }
        ... on MalwareAnalysis {
          result_name
        }
        ... on DataComponent {
          name
        }
        ... on DataSource {
          name
        }
        ... on ThreatActor {
          name
        }
        ... on Tool {
          name
        }
        ... on Vulnerability {
          name
        }
        ... on Incident {
          name
        }
        ... on StixCyberObservable {
          observable_value
        }
      }
    }
  }
`;

const stixCoreRelationshipCreationFromRelationFromMutation = graphql`
  mutation StixCoreRelationshipCreationFromRelationFromMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      ...EntityStixCoreRelationshipLineFrom_node
    }
  }
`;

const stixCoreRelationshipCreationFromRelationToMutation = graphql`
  mutation StixCoreRelationshipCreationFromRelationToMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      ...EntityStixCoreRelationshipLineTo_node
    }
  }
`;

type TargetEntity = StixCoreRelationshipCreationFromEntityStixCoreObjectsLine_node$data;
type SourceEntity = NonNullable<StixCoreRelationshipCreationFromRelationQuery$data['stixCoreRelationship']>;
type SearchPaginationOptions = Omit<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables, 'count'>;

interface StixCoreRelationshipCreationFromRelationSelectEntityProps {
  storageKey: string;
  initialValues: LocalStorage;
  dataColumns: DataTableProps['dataColumns'];
  searchPaginationOptions: SearchPaginationOptions;
  contextFilters: FilterGroup;
  targetTypes: string[];
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  createButton: ReactNode;
  numberOfSelectedElements: number;
  onContinue: () => void;
}

// Own component so that the entities are only queried once the drawer shows the list
const StixCoreRelationshipCreationFromRelationSelectEntity: FunctionComponent<StixCoreRelationshipCreationFromRelationSelectEntityProps> = ({
  storageKey,
  initialValues,
  dataColumns,
  searchPaginationOptions,
  contextFilters,
  targetTypes,
  setNumberOfElements,
  createButton,
  numberOfSelectedElements,
  onContinue,
}) => {
  const { t_i18n } = useFormatter();
  const [tableRootRef, setTableRootRef] = useState<HTMLDivElement | null>(null);
  const queryRef = useQueryLoading<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery>(
    stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    { ...searchPaginationOptions, count: 25 },
  );
  const preloadedPaginationProps = {
    linesQuery: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    linesFragment: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  } as UsePreloadedPaginationFragment<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery>;
  return (
    <>
      <div style={{ flex: '1 0 0', overflow: 'hidden' }} ref={setTableRootRef}>
        {queryRef && (
          <DataTable
            disableToolBar
            disableNavigation
            removeSelectAll
            selectOnLineClick
            hideSavedFilters
            variant={DataTableVariant.inline}
            rootRef={tableRootRef ?? undefined}
            dataColumns={dataColumns}
            resolvePath={(data: StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data) => data.stixCoreObjects?.edges?.map((n) => n?.node)}
            storageKey={storageKey}
            lineFragment={stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment}
            initialValues={initialValues}
            contextFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            entityTypes={targetTypes}
            availableEntityTypes={targetTypes}
            createButton={createButton}
          />
        )}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: 16 }}>
        <Button
          disabled={numberOfSelectedElements < 1}
          onClick={onContinue}
          endIcon={<ChevronRightOutlined />}
        >
          {t_i18n('Continue')}
        </Button>
      </div>
    </>
  );
};

interface StixCoreRelationshipCreationFromRelationSourceProps {
  queryRef: PreloadedQuery<StixCoreRelationshipCreationFromRelationQuery>;
  children: (sourceEntity: SourceEntity) => ReactElement;
}

const StixCoreRelationshipCreationFromRelationSource: FunctionComponent<StixCoreRelationshipCreationFromRelationSourceProps> = ({
  queryRef,
  children,
}) => {
  const { stixCoreRelationship } = usePreloadedQuery(stixCoreRelationshipCreationFromRelationQuery, queryRef);
  if (!stixCoreRelationship) {
    return <Loader variant={LoaderVariant.container} />;
  }
  return children(stixCoreRelationship);
};

interface StixCoreRelationshipCreationFromRelationLoaderProps {
  entityId: string;
  children: (sourceEntity: SourceEntity) => ReactElement;
}

// Mounted in the drawer, so that the relationship is only queried once the drawer is opened
const StixCoreRelationshipCreationFromRelationLoader: FunctionComponent<StixCoreRelationshipCreationFromRelationLoaderProps> = ({
  entityId,
  children,
}) => {
  const queryRef = useQueryLoading<StixCoreRelationshipCreationFromRelationQuery>(
    stixCoreRelationshipCreationFromRelationQuery,
    { id: entityId },
  );
  if (!queryRef) {
    return <Loader variant={LoaderVariant.container} />;
  }
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <StixCoreRelationshipCreationFromRelationSource queryRef={queryRef}>
        {children}
      </StixCoreRelationshipCreationFromRelationSource>
    </Suspense>
  );
};

interface StixCoreRelationshipCreationFromRelationProps {
  entityId: string;
  onlyObservables?: boolean;
  isRelationReversed?: boolean;
  stixCoreObjectTypes?: string[];
  allowedRelationshipTypes?: string[];
  paginationOptions?: Record<string, unknown>;
}

const StixCoreRelationshipCreationFromRelation: FunctionComponent<StixCoreRelationshipCreationFromRelationProps> = ({
  entityId,
  onlyObservables,
  isRelationReversed,
  stixCoreObjectTypes,
  allowedRelationshipTypes,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);
  const [openCreateEntity, setOpenCreateEntity] = useState(false);
  const [openCreateObservable, setOpenCreateObservable] = useState(false);

  const targetTypes = stixCoreObjectTypes && stixCoreObjectTypes.length > 0
    ? stixCoreObjectTypes
    : [onlyObservables ? 'Stix-Cyber-Observable' : 'Stix-Core-Object'];
  const showSDOCreation = !onlyObservables;
  const showSCOCreation = onlyObservables || targetTypes.includes('Stix-Core-Object') || targetTypes.includes('Stix-Cyber-Observable');
  const storageKey = `relation-add-linked-entities-${targetTypes}`;
  const initialValues = {
    searchTerm: '',
    sortBy: '_score',
    orderAsc: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers } = usePaginationLocalStorage<SearchPaginationOptions>(
    storageKey,
    initialValues,
    true,
  );
  // Selection of the list, shared with the DataTable through its storage key
  const {
    selectedElements,
    numberOfSelectedElements,
    handleClearSelectedElements,
  } = useEntityToggle<TargetEntity>(storageKey);
  const targetEntities = Object.values(selectedElements);
  const {
    sortBy,
    orderAsc,
    searchTerm,
    filters,
  } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext(targetTypes, filters);
  // Also the pagination options of the creations, so that a created entity is inserted in the list
  const searchPaginationOptions = {
    search: searchTerm,
    filters: contextFilters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  } as unknown as SearchPaginationOptions;
  const buildColumns = () => ({
    entity_type: {
      label: 'Type',
      percentWidth: 15,
      isSortable: true,
    },
    value: {
      label: 'Value',
      percentWidth: 33,
      isSortable: false,
    },
    createdBy: {
      label: 'Author',
      percentWidth: 15,
      isSortable: isRuntimeFieldEnable(),
    },
    objectLabel: {
      label: 'Labels',
      percentWidth: 22,
      isSortable: false,
    },
    objectMarking: {
      label: 'Marking',
      percentWidth: 15,
      isSortable: isRuntimeFieldEnable(),
    },
  });

  const handleOpen = () => setOpen(true);

  // Going back to the list remounts it with an empty selection
  const handleResetSelection = () => {
    setStep(0);
    handleClearSelectedElements();
  };

  const handleClose = () => {
    handleResetSelection();
    setOpen(false);
  };

  const commit = (input: Record<string, unknown>) => new Promise((resolve, reject) => {
    commitMutation({
      mutation: isRelationReversed
        ? stixCoreRelationshipCreationFromRelationToMutation
        : stixCoreRelationshipCreationFromRelationFromMutation,
      variables: { input },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_stixCoreRelationships',
          paginationOptions,
          'stixCoreRelationshipAdd',
        );
      },
      onError: reject,
      onCompleted: resolve,
    });
  });

  const onSubmit: FormikConfig<StixCoreRelationshipCreationFromEntityForm>['onSubmit'] = async (values, { setSubmitting, setErrors, resetForm }) => {
    setSubmitting(true);
    for (const targetEntity of targetEntities) {
      const fromEntityId = isRelationReversed ? targetEntity.id : entityId;
      const toEntityId = isRelationReversed ? entityId : targetEntity.id;
      const finalValues = R.pipe(
        R.assoc('confidence', parseInt(values.confidence, 10)),
        R.assoc('fromId', fromEntityId),
        R.assoc('toId', toEntityId),
        R.assoc('start_time', formatDate(values.start_time)),
        R.assoc('stop_time', formatDate(values.stop_time)),
        R.assoc('createdBy', values.createdBy?.value),
        R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
        R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
        R.assoc(
          'externalReferences',
          R.pluck('value', values.externalReferences),
        ),
      )(values);
      try {
        await commit(finalValues);
      } catch (error) {
        setSubmitting(false);
        return handleErrorInForm(error as Error, setErrors);
      }
    }
    setSubmitting(false);
    resetForm();
    handleClose();
    return true;
  };

  // Mounted in the drawer header and opened by the buttons of the list
  const renderCreations = () => (
    <>
      {showSDOCreation && (
        <StixDomainObjectCreation
          display={false}
          inputValue={searchTerm}
          speeddial={true}
          open={openCreateEntity}
          handleClose={() => setOpenCreateEntity(false)}
          stixDomainObjectTypes={stixCoreObjectTypes}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          creationCallback={undefined}
          onCompleted={undefined}
          isFromBulkRelation={undefined}
          confidence={undefined}
          defaultCreatedBy={undefined}
          defaultMarkingDefinitions={undefined}
        />
      )}
      {showSCOCreation && (
        <StixCyberObservableCreation
          display={false}
          contextual={true}
          inputValue={searchTerm}
          speeddial={true}
          open={openCreateObservable}
          handleClose={() => setOpenCreateObservable(false)}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          type={undefined}
          defaultCreatedBy={undefined}
          defaultMarkingDefinitions={undefined}
        />
      )}
    </>
  );

  const creationButtons = (
    <Stack direction="row" gap={1}>
      {showSDOCreation && (
        <Button
          disableElevation
          aria-label={t_i18n('Create an entity')}
          onClick={() => setOpenCreateEntity(true)}
        >
          {t_i18n('Create an entity')}
        </Button>
      )}
      {showSCOCreation && (
        <Button
          disableElevation
          aria-label={t_i18n('Create an observable')}
          onClick={() => setOpenCreateObservable(true)}
        >
          {t_i18n('Create an observable')}
        </Button>
      )}
    </Stack>
  );

  const renderSelectEntity = () => (
    <StixCoreRelationshipCreationFromRelationSelectEntity
      storageKey={storageKey}
      initialValues={initialValues}
      dataColumns={buildColumns()}
      searchPaginationOptions={searchPaginationOptions}
      contextFilters={contextFilters}
      targetTypes={targetTypes}
      setNumberOfElements={helpers.handleSetNumberOfElements}
      createButton={creationButtons}
      numberOfSelectedElements={numberOfSelectedElements}
      onContinue={() => setStep(1)}
    />
  );

  const renderForm = (sourceEntity: SourceEntity) => {
    let fromEntities: (SourceEntity | TargetEntity)[] = [sourceEntity];
    let toEntities: (SourceEntity | TargetEntity)[] = targetEntities;
    if (isRelationReversed) {
      fromEntities = targetEntities;
      toEntities = [sourceEntity];
    }

    return (
      <UserContext.Consumer>
        {({ schema }) => {
          const resolvePairRelationsTypes = (fromEntity: SourceEntity | TargetEntity, toEntity: SourceEntity | TargetEntity) => resolveRelationsTypes(
            fromEntity.parent_types.includes('Stix-Cyber-Observable')
              ? 'observable'
              : fromEntity.entity_type,
            toEntity.entity_type,
            schema?.schemaRelationsTypesMapping ?? new Map(),
          );
          // Only the types valid for every selected entity, as the same type is used for all relationships
          const relationshipTypes = R.uniq(targetEntities
            .map((targetEntity) => (isRelationReversed
              ? resolvePairRelationsTypes(targetEntity, sourceEntity)
              : resolvePairRelationsTypes(sourceEntity, targetEntity)))
            .reduce((acc, types) => R.intersection(acc, types))
            .filter(
              (n) => R.isNil(allowedRelationshipTypes)
                || allowedRelationshipTypes.length === 0
                || allowedRelationshipTypes.includes(n),
            ));
          return (
            <StixCoreRelationshipCreationForm
              fromEntities={fromEntities}
              toEntities={toEntities}
              relationshipTypes={relationshipTypes}
              handleResetSelection={handleResetSelection}
              onSubmit={onSubmit}
              handleClose={handleClose}
              handleReverseRelation={undefined}
              defaultStartTime={undefined}
              defaultStopTime={undefined}
              defaultConfidence={undefined}
              defaultCreatedBy={undefined}
              defaultMarkingDefinitions={undefined}
            />
          );
        }}
      </UserContext.Consumer>
    );
  };

  return (
    <div>
      <IconButton
        aria-label={t_i18n('Add relationship')}
        onClick={handleOpen}
        size="small"
        variant="tertiary"
      >
        <Add />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Create a relationship')}
        header={renderCreations()}
      >
        <StixCoreRelationshipCreationFromRelationLoader entityId={entityId}>
          {(sourceEntity) => (step === 0
            ? renderSelectEntity()
            : (
                <div style={{ marginTop: -20 }}>
                  {renderForm(sourceEntity)}
                </div>
              ))}
        </StixCoreRelationshipCreationFromRelationLoader>
      </Drawer>
    </div>
  );
};

export default StixCoreRelationshipCreationFromRelation;
