import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import { Button, CircularProgress, Fab, Typography } from '@mui/material';
import { ChevronRightOutlined } from '@mui/icons-material';
import { v4 as uuid } from 'uuid';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik';
import {
  StixCoreRelationshipCreationFromEntityForm,
  stixCoreRelationshipCreationFromEntityFromMutation,
  stixCoreRelationshipCreationFromEntityQuery,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
  stixCoreRelationshipCreationFromEntityToMutation,
  TargetEntity,
} from './StixCoreRelationshipCreationFromEntity';
import Drawer from '../drawer/Drawer';
import { commitMutation, handleErrorInForm, QueryRenderer } from '../../../../relay/environment';
import { StixCoreRelationshipCreationFromEntityQuery$data } from './__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../../components/i18n';
import { CreateRelationshipContext } from '../menus/CreateRelationshipContextProvider';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes } from '../../../../utils/stixTypeUtils';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { UserContext } from '../../../../utils/hooks/useAuth';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables } from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import {
  type StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery as StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQueryType,
} from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data } from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data.graphql';
import BulkRelationDialogContainer from '../bulk/dialog/BulkRelationDialogContainer';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { PaginationOptions } from '../../../../components/list_lines';
import { ModuleHelper } from '../../../../utils/platformModulesHelper';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import { isNodeInConnection } from '../../../../utils/store';
import { formatDate } from '../../../../utils/Time';

export const CreateRelationshipControlledDial = ({ onOpen }: {
  onOpen: () => void
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Button
      onClick={onOpen}
      variant='contained'
      disableElevation
      aria-label={t_i18n('Create Relationship')}
      style={{
        marginLeft: '3px',
        fontSize: 'small',
      }}
    >
      {t_i18n('Create Relationship')}
    </Button>
  );
};

interface HeaderProps {
  showCreates: boolean,
}

// Custom header prop for entity/observable creation buttons in initial step
export const Header: FunctionComponent<HeaderProps> = ({
  showCreates,
}) => {
  const { t_i18n } = useFormatter();

  const [openCreateEntity, setOpenCreateEntity] = useState<boolean>(false);
  const [openCreateObservable, setOpenCreateObservable] = useState<boolean>(false);
  const { state: { stixCoreObjectTypes } } = useContext(CreateRelationshipContext);
  const targetEntityTypes = (stixCoreObjectTypes ?? []).length > 0 ? stixCoreObjectTypes ?? ['Stix-Core-Object'] : ['Stix-Core-Object'];
  const targetStixDomainObjectTypes = computeTargetStixDomainObjectTypes(targetEntityTypes);
  const targetStixCyberObservableTypes = computeTargetStixCyberObservableTypes(targetEntityTypes);
  const showSDOCreation = targetStixDomainObjectTypes.length > 0;
  const showSCOCreation = targetStixCyberObservableTypes.length > 0;

  const handleOpenCreateEntity = () => setOpenCreateEntity(true);
  const handleCloseCreateEntity = () => setOpenCreateEntity(false);
  const handleOpenCreateObservable = () => setOpenCreateObservable(true);
  const handleCloseCreateObservable = () => setOpenCreateObservable(false);

  const entityTypes = [
    ...targetStixDomainObjectTypes,
    ...targetStixCyberObservableTypes,
  ];
  const filters: FilterGroup = {
    mode: 'and',
    filterGroups: [],
    filters: [{
      id: uuid(),
      key: 'entity_type',
      values: entityTypes,
      operator: 'eq',
      mode: 'or',
    }],
  };
  const searchPaginationOptions = {
    search: '',
    // filters: useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, entityTypes),
    filters: useBuildEntityTypeBasedFilterContext(entityTypes, filters),
    orderBy: '_score',
    orderMode: 'desc',
  };

  return (
    <div style={{
      width: '100%',
      display: 'flex',
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'center',
    }}
    >
      <Typography variant='subtitle2'>{t_i18n('Create a relationship')}</Typography>
      {showCreates
        && <div>
          {showSDOCreation && (
            <Button
              onClick={handleOpenCreateEntity}
              variant='outlined'
              disableElevation
              size='small'
              aria-label={t_i18n('Create an entity')}
              style={{
                marginLeft: '3px',
                marginRight: showSCOCreation ? undefined : '15px',
                fontSize: 'small',
              }}
            >
              {t_i18n('Create an entity')}
            </Button>
          )}
          {showSCOCreation && (
            <Button
              onClick={handleOpenCreateObservable}
              variant='outlined'
              disableElevation
              size='small'
              aria-label={t_i18n('Create an observable')}
              style={{
                marginLeft: '3px',
                marginRight: '15px',
                fontSize: 'small',
              }}
            >
              {t_i18n('Create an observable')}
            </Button>
          )}
          <StixDomainObjectCreation
            display={true}
            inputValue={''}
            paginationKey="Pagination_stixCoreObjects"
            paginationOptions={searchPaginationOptions}
            speeddial={true}
            open={openCreateEntity}
            handleClose={handleCloseCreateEntity}
            creationCallback={undefined}
            confidence={undefined}
            defaultCreatedBy={undefined}
            defaultMarkingDefinitions={undefined}
            stixDomainObjectTypes={entityTypes}
            onCompleted={undefined}
            isFromBulkRelation={undefined}
          />
          <StixCyberObservableCreation
            display={true}
            contextual={true}
            inputValue={''}
            paginationKey="Pagination_stixCoreObjects"
            paginationOptions={searchPaginationOptions}
            speeddial={true}
            open={openCreateObservable}
            handleClose={handleCloseCreateObservable}
            type={undefined}
            isFromBulkRelation={undefined}
            onCompleted={undefined}
          />
        </div>
      }
    </div>
  );
};

export const renderLoader = () => {
  return (
    <div style={{
      display: 'table',
      height: '100%',
      width: '100%',
    }}
    >
      <span style={{
        display: 'table-cell',
        verticalAlign: 'middle',
        textAlign: 'center',
      }}
      >
        <CircularProgress size={80} thickness={2}/>
      </span>
    </div>
  );
};

/**
 * The first page of the create relationship drawer: selecting the entity/entites
 * @param props.name The source entity's name
 * @param props.entity_id The source entity's id
 * @param props.entity_type The source entity's type
 * @param props.allowedRelationshipTypes
 * @param props.setTargetEntities Dispatch to set relationship target entities
 * @param props.targetEntities
 * @param props.handleNextStep Function to continue on to the next step
 * @returns JSX.Element
 */
const SelectEntity = ({
  name = '',
  entity_id,
  entity_type,
  allowedRelationshipTypes,
  setTargetEntities,
  targetEntities,
  handleNextStep,
}: {
  name?: string,
  entity_id: string,
  entity_type: string,
  allowedRelationshipTypes?: string[],
  setTargetEntities: React.Dispatch<TargetEntity[]>,
  targetEntities: TargetEntity[],
  handleNextStep: () => void,
}) => {
  const { t_i18n } = useFormatter();
  const { state: { stixCoreObjectTypes } } = useContext(CreateRelationshipContext);

  const typeFilters = (stixCoreObjectTypes ?? []).length > 0
    ? {
      mode: 'and',
      filterGroups: [],
      filters: [{
        id: uuid(),
        key: 'entity_type',
        values: stixCoreObjectTypes ?? [],
        operator: 'eq',
        mode: 'or',
      }],
    }
    : emptyFilterGroup;
  let virtualEntityTypes = stixCoreObjectTypes;
  if (virtualEntityTypes === undefined || virtualEntityTypes.length < 1) {
    virtualEntityTypes = ['Stix-Domain-Object', 'Stix-Cyber-Observable'];
  }
  const getLocalStorageKey = (entityId: string) => `${entityId}_stixCoreRelationshipCreationFromEntity`;

  const [sortBy, setSortBy] = useState('_score');
  const [orderAsc, setOrderAsc] = useState(false);

  const { viewStorage, helpers } = usePaginationLocalStorage<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables>(
    getLocalStorageKey(entity_id),
    { filters: typeFilters },
  );
  const { searchTerm = '', orderAsc: storageOrderAsc, sortBy: storageSortBy, filters } = viewStorage;

  useEffect(() => {
    if (storageSortBy && (storageSortBy !== sortBy)) setSortBy(storageSortBy);
    if (storageOrderAsc !== undefined && (storageOrderAsc !== orderAsc)) setOrderAsc(storageOrderAsc);
  }, [storageOrderAsc, storageSortBy]);

  const {
    selectedElements,
  } = useEntityToggle(getLocalStorageKey(entity_id));

  useEffect(() => {
    const newTargetEntities: TargetEntity[] = Object.values(selectedElements).map((item) => ({
      id: item.id,
      entity_type: item.entity_type ?? '',
      name: item.name ?? item.observable_value ?? '',
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
        percentWidth: 32,
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        percentWidth: 15,
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        percentWidth: 22,
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

  const initialValues = {
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };

  return (
    <div
      data-testid="stixCoreRelationshipCreationFromEntity-component"
      style={{
        height: '100%',
        width: '100%',
      }}
    >
      <UserContext.Consumer>
        {({ platformModuleHelpers }) => (
          <>
            {queryRef && (
              <div style={{ height: '100%' }} ref={setTableRootRef}>
                <DataTable
                  selectOnLineClick
                  disableNavigation
                  disableToolBar
                  disableSelectAll
                  rootRef={tableRootRef ?? undefined}
                  variant={DataTableVariant.inline}
                  dataColumns={buildColumns(platformModuleHelpers)}
                  resolvePath={(data: StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data) => data.stixCoreObjects?.edges?.map((n) => n?.node)}
                  storageKey={getLocalStorageKey(entity_id)}
                  lineFragment={stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment}
                  initialValues={initialValues}
                  toolbarFilters={contextFilters}
                  preloadedPaginationProps={preloadedPaginationProps}
                  entityTypes={virtualEntityTypes}
                  additionalHeaderButtons={[(
                    <BulkRelationDialogContainer
                      targetObjectTypes={['Stix-Domain-Object', 'Stix-Cyber-Observable']}
                      paginationOptions={searchPaginationOptions}
                      paginationKey="Pagination_stixCoreObjects"
                      key="BulkRelationDialogContainer"
                      stixDomainObjectId={entity_id}
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
      <Fab
        variant="extended"
        size="small"
        color="primary"
        onClick={() => handleNextStep()}
        disabled={Object.values(targetEntities).length < 1}
        style={{
          position: 'fixed',
          bottom: 40,
          right: 30,
          zIndex: 1001,
        }}
      >
        {t_i18n('Continue')} <ChevronRightOutlined />
      </Fab>
    </div>
  );
};

/**
 * The second page of the create relationship drawer: filling out the relationship
 * @param props.sourceEntity The source entity
 * @param props.targetEntities The target entities
 * @param props.handleClose Function called on close
 * @param props.allowedRelationshipTypes The relationship types available to be selected
 * @param props.isReversable Whether this relationship can be reversed
 * @param props.defaultStartTime The default start time
 * @param props.defaultStopTime The default stop time
 * @returns JSX.Element
 */
const RenderForm = ({
  sourceEntity,
  targetEntities,
  handleClose,
  allowedRelationshipTypes,
  isReversable,
  defaultStartTime,
  defaultStopTime,
}: {
  sourceEntity: TargetEntity,
  targetEntities: TargetEntity[],
  handleClose: () => void,
  allowedRelationshipTypes?: string[],
  isReversable?: boolean
  defaultStartTime?: string,
  defaultStopTime?: string,
}) => {
  const { state: {
    relationshipTypes: initialRelationshipTypes,
    reversed: initiallyReversed,
    onCreate,
    connectionKey,
    paginationOptions,
  } } = useContext(CreateRelationshipContext);
  const { schema } = useContext(UserContext);
  const [reversed, setReversed] = useState<boolean>(initiallyReversed ?? false);

  const handleReverse = () => setReversed(!reversed);

  let fromEntities = [sourceEntity];
  let toEntities = targetEntities;
  if (reversed) {
    fromEntities = targetEntities;
    toEntities = [sourceEntity];
  }
  const resolvedRelationshipTypes = (initialRelationshipTypes ?? []).length > 0
    ? initialRelationshipTypes ?? []
    : resolveRelationsTypes(
      fromEntities[0].entity_type,
      toEntities[0].entity_type,
      schema?.schemaRelationsTypesMapping ?? new Map(),
    );

  const relationshipTypes = resolvedRelationshipTypes.filter(
    (relType) => allowedRelationshipTypes === undefined
      || allowedRelationshipTypes.length === 0
      || allowedRelationshipTypes.includes('stix-core-relationship')
      || allowedRelationshipTypes.includes(relType),
  );
  const startTime = defaultStartTime ?? (new Date()).toISOString();
  const stopTime = defaultStopTime ?? (new Date()).toISOString();

  const commit = (finalValues: object) => {
    return new Promise((resolve, reject) => {
      commitMutation({
        mutation: reversed
          ? stixCoreRelationshipCreationFromEntityToMutation
          : stixCoreRelationshipCreationFromEntityFromMutation,
        variables: { input: finalValues },
        updater: (store: RecordSourceSelectorProxy) => {
          if (typeof onCreate !== 'function') {
            const userProxy = store.get(store.getRoot().getDataID());
            const payload = store.getRootField('stixCoreRelationshipAdd');

            const fromOrTo = reversed ? 'from' : 'to';
            const createdNode = connectionKey && payload !== null
              ? payload.getLinkedRecord(fromOrTo)
              : payload;
            const connKey = connectionKey ?? 'Pagination_stixCoreRelationships';
            // When using connectionKey we use less props of PaginationOptions, we need to filter them
            let conn;
            if (userProxy && paginationOptions) {
              conn = ConnectionHandler.getConnection(
                userProxy,
                connKey,
                paginationOptions,
              );
            }

            if (conn && payload !== null
              && !isNodeInConnection(payload, conn)
                && !isNodeInConnection(payload.getLinkedRecord(fromOrTo), conn)
            ) {
              const newEdge = payload.setLinkedRecord(createdNode, 'node');
              ConnectionHandler.insertEdgeBefore(conn, newEdge);
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
      const fromEntityId = reversed ? targetEntity.id : sourceEntity.id;
      const toEntityId = reversed ? sourceEntity.id : targetEntity.id;
      const finalValues = {
        ...values,
        confidence: parseInt(values.confidence, 10),
        fromId: fromEntityId,
        toId: toEntityId,
        start_time: formatDate(values.start_time),
        stop_time: formatDate(values.stop_time),
        killChainPhases: values.killChainPhases.map((kcp) => kcp.value),
        createdBy: values.createdBy?.value,
        objectMarking: values.objectMarking.map((marking) => marking.value),
        externalReferences: values.externalReferences.map((ref) => ref.value),
      };
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

  return (
    <StixCoreRelationshipCreationForm
      fromEntities={fromEntities}
      toEntities={toEntities}
      relationshipTypes={relationshipTypes}
      handleReverseRelation={isReversable ? handleReverse : undefined}
      handleResetSelection={handleClose}
      onSubmit={onSubmit}
      handleClose={handleClose}
      defaultStartTime={startTime}
      defaultStopTime={stopTime}
      defaultConfidence={undefined}
      defaultCreatedBy={undefined}
      defaultMarkingDefinitions={undefined}
    />
  );
};

interface StixCoreRelationshipCreationFromControlledDialProps {
  id: string,
  allowedRelationshipTypes?: string[],
  isReversable?: boolean,
  defaultStartTime?: string,
  defaultStopTime?: string,
  controlledDial?: ({ onOpen }: { onOpen: () => void }) => React.ReactElement,
}

const StixCoreRelationshipCreationFromControlledDial: FunctionComponent<StixCoreRelationshipCreationFromControlledDialProps> = ({
  id,
  allowedRelationshipTypes,
  isReversable = false,
  defaultStartTime,
  defaultStopTime,
  controlledDial,
}) => {
  const [step, setStep] = useState<number>(0);
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);

  const reset = () => {
    setStep(0);
    setTargetEntities([]);
  };

  return (
    <Drawer
      title={''} // Defined in custom header prop
      controlledDial={controlledDial ?? CreateRelationshipControlledDial}
      onClose={reset}
      header={<Header showCreates={step === 0} />}
      containerStyle={{
        minHeight: '100vh',
      }}
    >
      {({ onClose }) => (
        <QueryRenderer
          query={stixCoreRelationshipCreationFromEntityQuery}
          variables={{ id }}
          render={({ props }: { props: StixCoreRelationshipCreationFromEntityQuery$data }) => {
            if (props?.stixCoreObject) {
              const { name, entity_type, observable_value } = props.stixCoreObject;
              return <div style={{
                display: 'flex',
                flexDirection: 'column',
                height: '100%',
              }}
                     >
                {step === 0 && (
                  <SelectEntity
                    name={name ?? observable_value}
                    entity_id={id}
                    entity_type={entity_type}
                    allowedRelationshipTypes={allowedRelationshipTypes}
                    setTargetEntities={setTargetEntities}
                    targetEntities={targetEntities}
                    handleNextStep={() => setStep(1)}
                  />
                )}
                {step === 1 && (
                  <RenderForm
                    sourceEntity={props.stixCoreObject}
                    targetEntities={targetEntities}
                    handleClose={() => {
                      reset();
                      onClose();
                    }}
                    allowedRelationshipTypes={allowedRelationshipTypes}
                    isReversable={isReversable}
                    defaultStartTime={defaultStartTime}
                    defaultStopTime={defaultStopTime}
                  />
                )}
              </div>;
            }
            return renderLoader();
          }}
        />
      )}
    </Drawer>
  );
};

export default StixCoreRelationshipCreationFromControlledDial;
