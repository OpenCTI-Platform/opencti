import React, { FunctionComponent, useEffect, useRef, useState, Suspense } from 'react';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import IconButton from '@mui/material/IconButton';
import { Add, ChevronRightOutlined } from '@mui/icons-material';
import Fab from '@mui/material/Fab';
import CircularProgress from '@mui/material/CircularProgress';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import makeStyles from '@mui/styles/makeStyles';
import SpeedDial from '@mui/material/SpeedDial';
import SpeedDialIcon from '@mui/material/SpeedDialIcon';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import { GlobeModel, HexagonOutline } from 'mdi-material-ui';
import { StixCoreRelationshipCreationFromEntityQuery$data } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import { Option } from '@components/common/form/ReferenceField';
import { UsePreloadedPaginationFragment } from 'src/utils/hooks/usePreloadedPaginationFragment';
import { usePaginationLocalStorage } from 'src/utils/hooks/useLocalStorage';
import BulkRelationDialogContainer from '@components/common/bulk/dialog/BulkRelationDialogContainer';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data.graphql';
import { PaginationOptions } from 'src/components/list_lines';
import Drawer from '@components/common/drawer/Drawer';
import { getMainRepresentative } from 'src/utils/defaultRepresentatives';
import Loader, { LoaderVariant } from 'src/components/Loader';
import { commitMutation, handleErrorInForm, QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { formatDate } from '../../../../utils/Time';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import { isNodeInConnection } from '../../../../utils/store';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import {
  type StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery as StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQueryType,
} from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import type { Theme } from '../../../../components/Theme';
import { ModuleHelper } from '../../../../utils/platformModulesHelper';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1001,
  },
  continue: {
    position: 'fixed',
    bottom: 40,
    right: 30,
    zIndex: 1001,
  },
  container: {
    flex: '1 0 0',
    overflow: 'hidden',
  },
}));

export const stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery = graphql`
  query StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data
    @arguments(
      types: $types
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;
export const stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment = graphql`
  fragment StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesRefetchQuery") {
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
              name
            }
          }
          creators {
            id
            name
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...StixCoreRelationshipCreationFromEntityStixCoreObjectsLine_node
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
export const stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment = graphql`
  fragment StixCoreRelationshipCreationFromEntityStixCoreObjectsLine_node on StixCoreObject {
    id
    draftVersion {
      draft_id
      draft_operation
    }
    standard_id
    parent_types
    entity_type
    created_at
    ... on AttackPattern {
      name
      description
      aliases
      x_mitre_id
    }
    ... on Campaign {
      name
      description
      aliases
    }
    ... on Note {
      attribute_abstract
      content
    }
    ... on ObservedData {
      name
      first_observed
      last_observed
    }
    ... on Opinion {
      opinion
      explanation
    }
    ... on Report {
      name
      description
    }
    ... on Grouping {
      name
      description
    }
    ... on CourseOfAction {
      name
      description
      x_opencti_aliases
      x_mitre_id
    }
    ... on Individual {
      name
      description
      x_opencti_aliases
    }
    ... on Organization {
      name
      description
      x_opencti_aliases
    }
    ... on Sector {
      name
      description
      x_opencti_aliases
    }
    ... on System {
      name
      description
      x_opencti_aliases
    }
    ... on Indicator {
      name
      description
    }
    ... on Infrastructure {
      name
      description
    }
    ... on IntrusionSet {
      name
      aliases
      description
    }
    ... on Position {
      name
      description
      x_opencti_aliases
    }
    ... on City {
      name
      description
      x_opencti_aliases
    }
    ... on AdministrativeArea {
      name
      description
      x_opencti_aliases
    }
    ... on Country {
      name
      description
      x_opencti_aliases
    }
    ... on Region {
      name
      description
      x_opencti_aliases
    }
    ... on Malware {
      name
      aliases
      description
    }
    ... on MalwareAnalysis {
      result_name
    }
    ... on ThreatActor {
      name
      aliases
      description
    }
    ... on Tool {
      name
      aliases
      description
    }
    ... on Vulnerability {
      name
      description
    }
    ... on Incident {
      name
      aliases
      description
    }
    ... on Event {
      name
      description
      aliases
    }
    ... on Channel {
      name
      description
      aliases
    }
    ... on Narrative {
      name
      description
      aliases
    }
    ... on Language {
      name
      aliases
    }
    ... on DataComponent {
      name
    }
    ... on DataSource {
      name
    }
    ... on Case {
      name
    }
    ... on StixCyberObservable {
      observable_value
    }
    createdBy {
      id
      entity_type
      ... on Identity {
        name
      }
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    creators {
      id
      name
    }
  }

`;

const stixCoreRelationshipCreationFromEntityQuery = graphql`
  query StixCoreRelationshipCreationFromEntityQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      parent_types
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
      ... on Event {
        name
      }
      ... on Channel {
        name
      }
      ... on Narrative {
        name
      }
      ... on Language {
        name
      }
      ... on DataComponent {
        name
      }
      ... on DataSource {
        name
      }
      ... on Case {
        name
      }
      ... on MalwareAnalysis {
        result_name
      }
      ... on StixCyberObservable {
        observable_value
      }
    }
  }
`;

export const stixCoreRelationshipCreationFromEntityFromMutation = graphql`
  mutation StixCoreRelationshipCreationFromEntityFromMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      ...EntityStixCoreRelationshipLineAll_node
    }
  }
`;

const stixCoreRelationshipCreationFromEntityToMutation = graphql`
  mutation StixCoreRelationshipCreationFromEntityToMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      ...EntityStixCoreRelationshipLineAll_node
    }
  }
`;

interface StixCoreRelationshipCreationFromEntityProps {
  entityId: string;
  allowedRelationshipTypes?: string[];
  isRelationReversed?: boolean;
  targetStixDomainObjectTypes?: string[];
  targetStixCyberObservableTypes?: string[];
  defaultStartTime: string;
  defaultStopTime: string;
  paginationOptions: Record<string, unknown>;
  connectionKey?: string;
  paddingRight: number;
  variant?: string;
  targetEntities?: TargetEntity[];
  onCreate?: () => void;
  openExports?: boolean;
  handleReverseRelation?: () => void;
}

interface StixCoreRelationshipCreationFromEntityForm {
  confidence: string;
  start_time: string;
  stop_time: string;
  createdBy: Option;
  killChainPhases: Option[];
  objectMarking: Option[];
  externalReferences: Option[];
}

export interface TargetEntity {
  id: string;
  entity_type: string;
  name?: string;
}

const getLocalStorageKey = (entityId: string) => `${entityId}_stixCoreRelationshipCreationFromEntity`;

const StixCoreRelationshipCreationFromEntity: FunctionComponent<StixCoreRelationshipCreationFromEntityProps> = (props) => {
  const {
    targetEntities: targetEntitiesProps = [],
    entityId,
    paddingRight,
    paginationOptions,
    isRelationReversed,
    connectionKey,
    allowedRelationshipTypes,
    defaultStartTime,
    defaultStopTime,
    targetStixDomainObjectTypes = [],
    targetStixCyberObservableTypes = [],
    variant = undefined,
    onCreate = undefined,
    openExports = false,
    handleReverseRelation = undefined,
  } = props;
  let isOnlySDOs = false;
  let isOnlySCOs = false;
  let actualTypeFilterValues = [
    ...(targetStixDomainObjectTypes ?? []),
    ...(targetStixCyberObservableTypes ?? []),
  ];
  let virtualEntityTypes = ['Stix-Domain-Object', 'Stix-Cyber-Observable'];
  if (
    (targetStixDomainObjectTypes ?? []).length > 0
    && (targetStixCyberObservableTypes ?? []).length === 0
  ) {
    isOnlySDOs = true;
    virtualEntityTypes = targetStixDomainObjectTypes;
    if (!targetStixDomainObjectTypes.includes('Stix-Domain-Object')) {
      actualTypeFilterValues = targetStixDomainObjectTypes;
    }
  } else if (
    (targetStixCyberObservableTypes ?? []).length > 0
    && (targetStixDomainObjectTypes ?? []).length === 0
  ) {
    isOnlySCOs = true;
    virtualEntityTypes = targetStixCyberObservableTypes;
    if (!targetStixDomainObjectTypes.includes('Stix-Cyber-Observable')) {
      actualTypeFilterValues = targetStixCyberObservableTypes;
    }
  } else if (
    (targetStixCyberObservableTypes ?? []).length > 0
    && (targetStixDomainObjectTypes ?? []).length > 0
  ) {
    virtualEntityTypes = [
      ...targetStixDomainObjectTypes,
      ...targetStixCyberObservableTypes,
    ];
  }

  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(targetEntitiesProps.length !== 0);
  const [openSpeedDial, setOpenSpeedDial] = useState(false);
  const [openCreateEntity, setOpenCreateEntity] = useState(false);
  const [openCreateObservable, setOpenCreateObservable] = useState(false);
  const [step, setStep] = useState(targetEntitiesProps.length === 0 ? 0 : 1);
  const [targetEntities, setTargetEntities] = useState(
    targetEntitiesProps,
  );
  useEffect(() => {
    if (!R.equals(targetEntitiesProps, targetEntities) && targetEntitiesProps.length > targetEntities.length) {
      setTargetEntities(targetEntitiesProps);
      setStep(targetEntitiesProps.length === 0 ? 0 : 1);
      setOpen(targetEntitiesProps.length !== 0);
    }
  }, [targetEntitiesProps]);
  const [sortBy, setSortBy] = useState('_score');
  const [orderAsc, setOrderAsc] = useState(false);

  const containerRef = useRef(null);

  const { viewStorage, helpers } = usePaginationLocalStorage<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables>(
    getLocalStorageKey(entityId),
    {},
    true,
  );
  const { searchTerm = '', orderAsc: storageOrderAsc, sortBy: storageSortBy, filters } = viewStorage;

  useEffect(() => {
    if (storageSortBy && (storageSortBy !== sortBy)) setSortBy(storageSortBy);
    if (storageOrderAsc !== undefined && (storageOrderAsc !== orderAsc)) setOrderAsc(storageOrderAsc);
  }, [storageOrderAsc, storageSortBy]);

  const handleOpenSpeedDial = () => {
    setOpenSpeedDial(true);
  };

  const handleCloseSpeedDial = () => {
    setOpenSpeedDial(false);
  };

  const handleOpenCreateEntity = () => {
    setOpenCreateEntity(true);
    setOpenSpeedDial(false);
  };

  const handleCloseCreateEntity = () => {
    setOpenCreateEntity(false);
    setOpenSpeedDial(false);
  };

  const handleOpenCreateObservable = () => {
    setOpenCreateObservable(true);
    setOpenSpeedDial(false);
  };

  const handleCloseCreateObservable = () => {
    setOpenCreateObservable(false);
    setOpenSpeedDial(false);
  };

  const handleClose = () => {
    setOpen(false);
    setStep(0);
    setTargetEntities([]);
  };

  const commit = (finalValues: object) => {
    return new Promise((resolve, reject) => {
      commitMutation({
        mutation: isRelationReversed
          ? stixCoreRelationshipCreationFromEntityToMutation
          : stixCoreRelationshipCreationFromEntityFromMutation,
        variables: { input: finalValues },
        updater: (store: RecordSourceSelectorProxy) => {
          if (typeof onCreate !== 'function') {
            const userProxy = store.get(store.getRoot().getDataID());
            const payload = store.getRootField('stixCoreRelationshipAdd');

            const createdNode = connectionKey && payload !== null
              ? payload.getLinkedRecord(isRelationReversed ? 'from' : 'to')
              : payload;
            const connKey = connectionKey || 'Pagination_stixCoreRelationships';
            let conn;
            // When using connectionKey we use less props of PaginationOptions (ex: count),
            // we need to filter them to prevent getConnection to fail
            const { count: _, ...options } = paginationOptions;

            if (userProxy) {
              conn = ConnectionHandler.getConnection(
                userProxy,
                connKey,
                options,
              );
            }

            if (conn && payload !== null
              && !isNodeInConnection(payload, conn)
              && !isNodeInConnection(payload.getLinkedRecord(isRelationReversed ? 'from' : 'to'), conn)
            ) {
              const newEdge = payload.setLinkedRecord(createdNode, 'node');
              ConnectionHandler.insertEdgeBefore(conn, newEdge);

              helpers.handleSetNumberOfElements({ });
            }
          }
        },
        optimisticUpdater: undefined,
        setSubmitting: undefined,
        optimisticResponse: undefined,
        onError: (error: Error) => {
          reject(error);
        },
        onCompleted: (response: Response) => {
          resolve(response);
        },
      });
    });
  };

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
        R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
        R.assoc('createdBy', values.createdBy?.value),
        R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
        R.assoc(
          'externalReferences',
          R.pluck('value', values.externalReferences),
        ),
      )(values);
      try {
        // eslint-disable-next-line no-await-in-loop
        await commit(finalValues);
      } catch (error) {
        setSubmitting(false);
        return handleErrorInForm(error, setErrors);
      }
    }
    setSubmitting(false);
    resetForm();
    handleClose();
    if (typeof onCreate === 'function') {
      onCreate();
    }
    return true;
  };

  const handleResetSelection = () => {
    setStep(0);
    setTargetEntities([]);
  };

  const handleNextStep = () => {
    setStep(1);
  };

  const {
    selectedElements,
  } = useEntityToggle(getLocalStorageKey(entityId));

  useEffect(() => {
    const newTargetEntities: TargetEntity[] = Object.values(selectedElements).map((item) => ({
      id: item.id,
      entity_type: item.entity_type ?? '',
      name: getMainRepresentative(item),
    }));
    setTargetEntities(newTargetEntities);
  }, [selectedElements]);

  const buildColumns = (platformModuleHelpers: ModuleHelper | undefined) => {
    const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable();
    return {
      entity_type: {
        label: 'Type',
        percentWidth: 15,
        isSortable: true,
      },
      value: {
        label: 'Value',
        percentWidth: 35,
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        percentWidth: 15,
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        percentWidth: 20,
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        percentWidth: 15,
        isSortable: isRuntimeSort,
      },
    };
  };
  const contextFilters = useBuildEntityTypeBasedFilterContext(virtualEntityTypes, filters);
  const searchPaginationOptions: PaginationOptions = {
    search: searchTerm,
    filters: contextFilters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  } as PaginationOptions;

  const queryRef = useQueryLoading<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQueryType>(
    stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    { ...searchPaginationOptions, count: 100 } as StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables,
  );

  const preloadedPaginationProps = {
    linesQuery: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    linesFragment: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQueryType>;

  const [tableRootRef, setTableRootRef] = useState<HTMLDivElement | null>(null);

  const renderSelectEntity = (entity_type: string, name = '') => {
    return (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          height: '100%',
        }}
      >
        <div data-testid="stixCoreRelationshipCreationFromEntity-component" className={classes.container}>
          <UserContext.Consumer>
            {({ platformModuleHelpers }) => (
              <>
                {queryRef && (
                  <div style={{ height: '100%' }} ref={setTableRootRef}>
                    <DataTable
                      disableToolBar
                      disableSelectAll
                      disableNavigation
                      selectOnLineClick
                      variant={DataTableVariant.inline}
                      rootRef={tableRootRef ?? undefined}
                      dataColumns={buildColumns(platformModuleHelpers)}
                      resolvePath={(data: StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data) => data.stixCoreObjects?.edges?.map((n) => n?.node)}
                      storageKey={getLocalStorageKey(entityId)}
                      lineFragment={stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment}
                      initialValues={{}}
                      toolbarFilters={contextFilters}
                      preloadedPaginationProps={preloadedPaginationProps}
                      entityTypes={virtualEntityTypes}
                      availableEntityTypes={virtualEntityTypes}
                      additionalHeaderButtons={[(
                        <BulkRelationDialogContainer
                          targetObjectTypes={[...targetStixDomainObjectTypes, ...targetStixCyberObservableTypes]}
                          paginationOptions={searchPaginationOptions}
                          paginationKey="Pagination_stixCoreObjects"
                          key="BulkRelationDialogContainer"
                          stixDomainObjectId={entityId}
                          stixDomainObjectName={name}
                          stixDomainObjectType={entity_type}
                          defaultRelationshipType={allowedRelationshipTypes?.[0]}
                          selectedEntities={targetEntities}
                        />
                      )]}
                    />
                  </div>
                )}
              </>
            )}
          </UserContext.Consumer>
          {targetEntities.length === 0 && isOnlySDOs && (
            <StixDomainObjectCreation
              display={open}
              inputValue={searchTerm}
              paginationKey="Pagination_stixCoreObjects"
              paginationOptions={searchPaginationOptions}
              stixDomainObjectTypes={actualTypeFilterValues}
              creationCallback={undefined}
              confidence={undefined}
              defaultCreatedBy={undefined}
              defaultMarkingDefinitions={undefined}
              isFromBulkRelation={undefined}
              open={undefined}
              speeddial={undefined}
              handleClose={undefined}
              onCompleted={undefined}
            />
          )}
          {targetEntities.length === 0 && isOnlySCOs && (
            <StixCyberObservableCreation
              display={open}
              contextual={true}
              inputValue={searchTerm}
              paginationKey="Pagination_stixCoreObjects"
              paginationOptions={searchPaginationOptions}
            />
          )}
          {targetEntities.length === 0 && !isOnlySDOs && !isOnlySCOs && (
            <>
              <SpeedDial
                className={classes.createButton}
                ariaLabel="Create"
                icon={<SpeedDialIcon />}
                onClose={handleCloseSpeedDial}
                onOpen={handleOpenSpeedDial}
                open={openSpeedDial}
                FabProps={{
                  color: 'primary',
                }}
              >
                <SpeedDialAction
                  title={t_i18n('Create an observable')}
                  icon={<HexagonOutline />}
                  tooltipTitle={t_i18n('Create an observable')}
                  onClick={handleOpenCreateObservable}
                  FabProps={{
                    classes: { root: classes.speedDialButton },
                  }}
                />
                <SpeedDialAction
                  title={t_i18n('Create an entity')}
                  icon={<GlobeModel />}
                  tooltipTitle={t_i18n('Create an entity')}
                  onClick={handleOpenCreateEntity}
                  FabProps={{
                    classes: { root: classes.speedDialButton },
                  }}
                />
              </SpeedDial>
              <StixDomainObjectCreation
                display={open}
                inputValue={searchTerm}
                paginationKey="Pagination_stixCoreObjects"
                paginationOptions={searchPaginationOptions}
                speeddial={true}
                open={openCreateEntity}
                handleClose={handleCloseCreateEntity}
                onCompleted={undefined}
                creationCallback={undefined}
                confidence={undefined}
                defaultCreatedBy={undefined}
                isFromBulkRelation={undefined}
                defaultMarkingDefinitions={undefined}
                stixDomainObjectTypes={undefined}
              />
              <StixCyberObservableCreation
                display={open}
                contextual={true}
                inputValue={searchTerm}
                paginationKey="Pagination_stixCoreObjects"
                paginationOptions={searchPaginationOptions}
                speeddial={true}
                open={openCreateObservable}
                handleClose={handleCloseCreateObservable}
              />
            </>
          )}
          {targetEntities.length > 0 && (
            <Fab
              variant="extended"
              className={classes.continue}
              size="small"
              color="primary"
              onClick={handleNextStep}
            >
              {t_i18n('Continue')}
              <ChevronRightOutlined />
            </Fab>
          )}
        </div>
      </div>
    );
  };

  const renderForm = (sourceEntity: TargetEntity) => {
    let fromEntities = [sourceEntity];
    let toEntities = targetEntities;
    if (isRelationReversed) {
      // eslint-disable-next-line prefer-destructuring
      fromEntities = targetEntities;
      toEntities = [sourceEntity];
    }
    return (
      <UserContext.Consumer>
        {({ schema }) => {
          const relationshipTypes = R.uniq(resolveRelationsTypes(
            fromEntities[0].entity_type,
            toEntities[0].entity_type,
            schema?.schemaRelationsTypesMapping ?? new Map(),
          ).filter(
            (n) => R.isNil(allowedRelationshipTypes)
              || allowedRelationshipTypes.length === 0
              || allowedRelationshipTypes.includes('stix-core-relationship')
              || allowedRelationshipTypes.includes(n),
          ));
          return (
            <StixCoreRelationshipCreationForm
              fromEntities={fromEntities}
              toEntities={toEntities}
              relationshipTypes={relationshipTypes}
              handleReverseRelation={handleReverseRelation}
              handleResetSelection={handleResetSelection}
              onSubmit={onSubmit}
              handleClose={handleClose}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              defaultConfidence={undefined}
              defaultCreatedBy={undefined}
              defaultMarkingDefinitions={undefined}
            />
          );
        }}
      </UserContext.Consumer>
    );
  };

  const renderLoader = () => {
    return (
      <div style={{ display: 'table', height: '100%', width: '100%' }}>
        <span
          style={{
            display: 'table-cell',
            verticalAlign: 'middle',
            textAlign: 'center',
          }}
        >
          <CircularProgress size={80} thickness={2} />
        </span>
      </div>
    );
  };

  return (
    <>
      {/* eslint-disable-next-line no-nested-ternary */}
      {variant === 'inLine' ? (
        <IconButton
          color="primary"
          aria-label="Label"
          onClick={() => setOpen(true)}
          style={{ float: 'left', margin: '-15px 0 0 -2px' }}
          size="large"
        >
          <Add fontSize="small" />
        </IconButton>
      ) : !openExports ? (
        <Fab
          onClick={() => setOpen(true)}
          color="primary"
          aria-label="Add"
          className={classes.createButton}
          style={{ right: paddingRight || 30 }}
        >
          <Add />
        </Fab>
      ) : (
        ''
      )}
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Create a relationship')}
        ref={containerRef}
      >
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <QueryRenderer
            query={stixCoreRelationshipCreationFromEntityQuery}
            variables={{ id: entityId }}
            render={({ props: renderProps }: ({ props: StixCoreRelationshipCreationFromEntityQuery$data })) => {
              if (renderProps && renderProps.stixCoreObject) {
                const { name, entity_type, observable_value } = renderProps.stixCoreObject;
                return (
                  <>
                    {step === 0 ? renderSelectEntity(entity_type, name || observable_value) : null}
                    {step === 1 ? renderForm(renderProps.stixCoreObject) : null}
                  </>
                );
              }
              return renderLoader();
            }}
          />
        </Suspense>
      </Drawer>
    </>
  );
};

export default StixCoreRelationshipCreationFromEntity;
