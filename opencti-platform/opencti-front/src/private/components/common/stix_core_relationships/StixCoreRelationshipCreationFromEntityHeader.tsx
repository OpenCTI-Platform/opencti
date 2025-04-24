import { Button, CircularProgress, Fab } from '@mui/material';
import React, { FunctionComponent, useEffect, useState } from 'react';
import { ChevronRightOutlined } from '@mui/icons-material';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import Drawer from '../drawer/Drawer';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data } from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data.graphql';
import BulkRelationDialogContainer from '../bulk/dialog/BulkRelationDialogContainer';
import { ModuleHelper } from '../../../../utils/platformModulesHelper';
import { UserContext } from '../../../../utils/hooks/useAuth';
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
import { useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { UseLocalStorageHelpers, usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables } from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import { PaginationOptions } from '../../../../components/list_lines';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import {
  type StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery as StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQueryType,
} from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { StixCoreRelationshipCreationFromEntityQuery } from './__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { commitMutation, handleErrorInForm } from '../../../../relay/environment';
import { isNodeInConnection } from '../../../../utils/store';
import { formatDate } from '../../../../utils/Time';

interface HeaderProps {
  show: boolean;
  showSDOs: boolean;
  showSCOs: boolean;
  searchTerm: string;
  searchPaginationOptions: PaginationOptions;
  actualTypeFilterValues: string[];
}

const Header: FunctionComponent<HeaderProps> = ({
  show,
  showSDOs,
  showSCOs,
  searchTerm,
  searchPaginationOptions,
  actualTypeFilterValues,
}) => {
  const { t_i18n } = useFormatter();
  const [openCreateObservable, setOpenCreateObservable] = useState<boolean>(false);

  const handleOpenCreateObservable = () => setOpenCreateObservable(true);
  const handleCloseCreateObservable = () => setOpenCreateObservable(false);

  return show && (
    <div
      style={{
        width: '100%',
        display: 'flex',
        justifyContent: 'end',
      }}
    >
      {showSDOs && (
        <StixDomainObjectCreation
          display={true}
          inputValue={searchTerm}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          speeddial={false}
          open={undefined}
          handleClose={undefined}
          onCompleted={undefined}
          creationCallback={undefined}
          confidence={undefined}
          defaultCreatedBy={undefined}
          isFromBulkRelation={undefined}
          defaultMarkingDefinitions={undefined}
          stixDomainObjectTypes={actualTypeFilterValues}
          controlledDialStyles={{ marginRight: '10px' }}
        />
      )}
      {showSCOs && (
        <Button
          onClick={handleOpenCreateObservable}
          variant='contained'
          style={{ marginRight: '10px' }}
        >
          {t_i18n('Create an observable')}
        </Button>
      )}
      <StixCyberObservableCreation
        display={true}
        contextual={true}
        inputValue={searchTerm}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
        speeddial={true}
        open={openCreateObservable}
        handleClose={handleCloseCreateObservable}
        type={undefined}
        defaultCreatedBy={undefined}
      />
    </div>
  );
};

interface SelectEntityStageProps {
  handleNextStep: () => void;
  storageKey: string;
  entityId: string;
  queryRef: PreloadedQuery<StixCoreRelationshipCreationFromEntityQuery, Record<string, unknown>>;
  targetStixDomainObjectTypes: string[];
  targetStixCyberObservableTypes: string[];
  allowedRelationshipTypes?: string[];
  targetEntities: TargetEntity[];
  setTargetEntities: React.Dispatch<React.SetStateAction<TargetEntity[]>>;
  searchPaginationOptions: PaginationOptions;
  helpers: UseLocalStorageHelpers;
  contextFilters: FilterGroup;
  virtualEntityTypes: string[];
}

const SelectEntityStage: FunctionComponent<SelectEntityStageProps> = ({
  handleNextStep,
  storageKey,
  entityId,
  queryRef: queryRefProps,
  targetStixDomainObjectTypes,
  targetStixCyberObservableTypes,
  allowedRelationshipTypes,
  targetEntities,
  setTargetEntities,
  searchPaginationOptions,
  helpers,
  contextFilters,
  virtualEntityTypes,
}) => {
  const { t_i18n } = useFormatter();
  const [tableRootRef, setTableRootRef] = useState<HTMLDivElement | null>(null);
  const { stixCoreObject } = usePreloadedQuery(
    stixCoreRelationshipCreationFromEntityQuery,
    queryRefProps,
  );

  // Handle element selection
  const { selectedElements } = useEntityToggle(storageKey);
  useEffect(() => {
    const newTargetEntities: TargetEntity[] = Object.values(selectedElements).map((item) => ({
      id: item.id,
      entity_type: item.entity_type ?? '',
      name: getMainRepresentative(item),
    }));
    setTargetEntities(newTargetEntities);
  }, [selectedElements]);

  // Column headers
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

  if (!stixCoreObject || !queryRef) {
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
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
      }}
    >
      <div style={{ height: '100%' }} ref={setTableRootRef}>
        <UserContext.Consumer>
          {({ platformModuleHelpers }) => (
            <DataTable
              disableToolBar
              disableSelectAll
              disableNavigation
              selectOnLineClick
              variant={DataTableVariant.inline}
              rootRef={tableRootRef ?? undefined}
              dataColumns={buildColumns(platformModuleHelpers)}
              resolvePath={(data: StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data) => data.stixCoreObjects?.edges?.map((n) => n?.node)}
              storageKey={storageKey}
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
                  stixDomainObjectName={stixCoreObject.name ?? ''}
                  stixDomainObjectType={stixCoreObject.entity_type}
                  defaultRelationshipType={allowedRelationshipTypes?.[0]}
                  selectedEntities={targetEntities}
                />
              )]}
            />
          )}
        </UserContext.Consumer>
      </div>
      <Fab
        variant="extended"
        size="small"
        color="primary"
        onClick={handleNextStep}
        disabled={targetEntities.length < 1}
        style={{
          position: 'fixed',
          bottom: 40,
          right: 30,
          zIndex: 1001,
        }}
      >
        {t_i18n('Continue')}
        <ChevronRightOutlined />
      </Fab>
    </div>
  );
};

interface CreateFormStageProps {
  targetEntities: TargetEntity[];
  queryRef: PreloadedQuery<StixCoreRelationshipCreationFromEntityQuery, Record<string, unknown>>;
  isRelationReversed?: boolean;
  allowedRelationshipTypes?: string[];
  handleReverseRelation?: () => void;
  handleResetSelection: () => void;
  handleClose: () => void;
  defaultStartTime: string;
  defaultStopTime: string;
  helpers: UseLocalStorageHelpers;
  entityId: string;
  paginationOptions: Record<string, unknown>;
  connectionKey?: string;
  onCreate?: () => void;
}

const CreateFormStage: FunctionComponent<CreateFormStageProps> = ({
  targetEntities,
  queryRef,
  isRelationReversed = false,
  allowedRelationshipTypes,
  handleReverseRelation,
  handleResetSelection,
  handleClose,
  defaultStartTime,
  defaultStopTime,
  helpers,
  entityId,
  paginationOptions,
  connectionKey,
  onCreate,
}) => {
  const { stixCoreObject } = usePreloadedQuery(
    stixCoreRelationshipCreationFromEntityQuery,
    queryRef,
  );

  if (!stixCoreObject) {
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
  }

  const sourceEntity: TargetEntity = stixCoreObject;
  let fromEntities = [sourceEntity];
  let toEntities = targetEntities;
  if (isRelationReversed) {
    fromEntities = targetEntities;
    toEntities = [sourceEntity];
  }

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
      const finalValues = {
        ...values,
        confidence: parseInt(values.confidence, 10),
        fromId: fromEntityId,
        toId: toEntityId,
        start_time: formatDate(values.start_time),
        stop_time: formatDate(values.stop_time),
        killChainPhases: values.killChainPhases.map((kcp) => kcp.value),
        createdBy: values.createdBy.value,
        objectMarking: values.objectMarking.map((om) => om.value),
        externalReferences: values.externalReferences.map((er) => er.value),
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
    <UserContext.Consumer>
      {({ schema }) => {
        const relationshipTypes = resolveRelationsTypes(
          fromEntities[0].entity_type,
          toEntities[0].entity_type,
          schema?.schemaRelationsTypesMapping ?? new Map(),
        ).filter( // Unique filter
          (value, index, self) => self.indexOf(value) === index,
        ).filter(
          (n) => allowedRelationshipTypes === null
            || allowedRelationshipTypes === undefined
            || allowedRelationshipTypes.length === 0
            || allowedRelationshipTypes.includes('stix-core-relationship')
            || allowedRelationshipTypes.includes(n),
        );
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

interface StixCoreRelationshipCreationFromEntityHeaderProps {
  entityId: string;
  targetStixDomainObjectTypes?: string[];
  targetStixCyberObservableTypes?: string[];
  allowedRelationshipTypes?: string[];
  targetEntities?: TargetEntity[];
  isRelationReversed?: boolean;
  handleReverseRelation?: () => void;
  defaultStartTime: string;
  defaultStopTime: string;
  paginationOptions: Record<string, unknown>;
  connectionKey?: string;
  onCreate?: () => void;
}

const StixCoreRelationshipCreationFromEntityHeader: FunctionComponent<
StixCoreRelationshipCreationFromEntityHeaderProps
> = ({
  entityId,
  targetStixDomainObjectTypes = [],
  targetStixCyberObservableTypes = [],
  allowedRelationshipTypes,
  targetEntities: initialTargetEntities = [],
  isRelationReversed,
  handleReverseRelation = undefined,
  defaultStartTime,
  defaultStopTime,
  paginationOptions,
  connectionKey,
  onCreate,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [step, setStep] = useState<number>(0);
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>(
    initialTargetEntities,
  );

  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    setOpen(false);
    setStep(0);
    setTargetEntities([]);
  };
  const handleResetSelection = () => {
    setStep(0);
    setTargetEntities([]);
  };

  const storageKey = `stixCoreRelationshipCreationFromEntity-${entityId}-${targetStixDomainObjectTypes.join('-')}-${targetStixCyberObservableTypes.join('-')}`;

  const [sortBy, setSortBy] = useState('_score');
  const [orderAsc, setOrderAsc] = useState(false);
  const { viewStorage, helpers } = usePaginationLocalStorage<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables>(
    storageKey,
    {},
    true,
  );
  const { searchTerm = '', orderAsc: storageOrderAsc, sortBy: storageSortBy, filters } = viewStorage;
  useEffect(() => {
    if (storageSortBy && (storageSortBy !== sortBy)) setSortBy(storageSortBy);
    if (storageOrderAsc !== undefined && (storageOrderAsc !== orderAsc)) setOrderAsc(storageOrderAsc);
  }, [storageOrderAsc, storageSortBy]);
  const virtualEntityTypes = ['Stix-Domain-Object', 'Stix-Cyber-Observable'];
  const contextFilters = useBuildEntityTypeBasedFilterContext(virtualEntityTypes, filters);
  const searchPaginationOptions: PaginationOptions = {
    search: searchTerm,
    filters: contextFilters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  } as PaginationOptions;

  const queryRef = useQueryLoading<
  StixCoreRelationshipCreationFromEntityQuery
  >(
    stixCoreRelationshipCreationFromEntityQuery,
    { id: entityId },
  );

  if (!queryRef) return <Loader variant={LoaderVariant.inElement} />;

  return (
    <>
      <Button
        onClick={handleOpen}
        variant='outlined'
        style={{ marginLeft: '6px' }}
      >
        {t_i18n('Create Relationship')}
      </Button>
      <Drawer
        title={t_i18n('Create a relationship')}
        open={open}
        onClose={handleClose}
        header={(
          <Header
            show={step < 1}
            showSDOs={targetStixDomainObjectTypes.length > 0}
            showSCOs={targetStixCyberObservableTypes.length > 0}
            searchTerm={searchTerm}
            searchPaginationOptions={searchPaginationOptions}
            actualTypeFilterValues={[
              ...targetStixDomainObjectTypes,
              ...targetStixCyberObservableTypes,
            ]}
          />
        )}
      >
        {step === 0
          ? (
            <SelectEntityStage
              handleNextStep={() => setStep(1)}
              storageKey={storageKey}
              entityId={entityId}
              queryRef={queryRef}
              targetStixDomainObjectTypes={targetStixDomainObjectTypes}
              targetStixCyberObservableTypes={targetStixCyberObservableTypes}
              allowedRelationshipTypes={allowedRelationshipTypes}
              targetEntities={targetEntities}
              setTargetEntities={setTargetEntities}
              searchPaginationOptions={searchPaginationOptions}
              helpers={helpers}
              contextFilters={contextFilters}
              virtualEntityTypes={virtualEntityTypes}
            />
          ) : (
            <CreateFormStage
              targetEntities={targetEntities}
              queryRef={queryRef}
              isRelationReversed={isRelationReversed}
              allowedRelationshipTypes={allowedRelationshipTypes}
              handleReverseRelation={handleReverseRelation}
              handleResetSelection={handleResetSelection}
              handleClose={handleClose}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              helpers={helpers}
              entityId={entityId}
              paginationOptions={paginationOptions}
              connectionKey={connectionKey}
              onCreate={onCreate}
            />
          )
        }
      </Drawer>
    </>
  );
};

export default StixCoreRelationshipCreationFromEntityHeader;
