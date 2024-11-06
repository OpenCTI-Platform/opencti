import {
  StixCoreRelationshipCreationFromEntityForm,
  stixCoreRelationshipCreationFromEntityFromMutation,
  stixCoreRelationshipCreationFromEntityQuery,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
  stixCoreRelationshipCreationFromEntityToMutation,
  TargetEntity,
} from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import { StixCoreRelationshipCreationFromEntityQuery } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { CreateRelationshipContext } from '@components/common/menus/CreateRelationshipContextProvider';
import { v4 as uuid } from 'uuid';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import CreateRelationshipControlledDial from '@components/common/stix_core_relationships/CreateRelationshipControlledDial';
import CreateRelationshipHeader from '@components/common/stix_core_relationships/CreateRelationshipHeader';
import Drawer from '@components/common/drawer/Drawer';
import StixCoreRelationshipCreationForm from '@components/common/stix_core_relationships/StixCoreRelationshipCreationForm';
import { FormikConfig } from 'formik/dist/types';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data.graphql';
import { ChevronRightOutlined } from '@mui/icons-material';
import Fab from '@mui/material/Fab';
import BulkRelationDialogContainer from '@components/common/bulk/dialog/BulkRelationDialogContainer';
import { PaginationOptions } from '../../../../components/list_lines';
import { UseLocalStorageHelpers, usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { commitMutation, handleErrorInForm } from '../../../../relay/environment';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { useFormatter } from '../../../../components/i18n';
import { UserContext } from '../../../../utils/hooks/useAuth';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import { isNodeInConnection } from '../../../../utils/store';
import { formatDate } from '../../../../utils/Time';

/**
 * The first page of the create relationship drawer: selecting the entity/entites
 * @param props.name The source entity's name
 * @param props.entity_id The source entity's id
 * @param props.entity_type The source entity's type
 * @param props.setTargetEntities Dispatch to set relationship target entities
 * @param props.targetEntities
 * @param props.handleNextStep Function to continue on to the next step
 * @returns JSX.Element
 */
const SelectEntity = ({
  name = '',
  entity_id,
  entity_type,
  setTargetEntities,
  targetEntities,
  handleNextStep,
  searchPaginationOptions,
  localStorageKey,
  helpers,
  contextFilters,
  virtualEntityTypes,
}: {
  name?: string,
  entity_id: string,
  entity_type: string,
  setTargetEntities: React.Dispatch<TargetEntity[]>,
  targetEntities: TargetEntity[],
  handleNextStep: () => void,
  searchPaginationOptions: PaginationOptions,
  localStorageKey: string,
  helpers: UseLocalStorageHelpers,
  contextFilters: FilterGroup,
  virtualEntityTypes: string[],
}) => {
  const { t_i18n } = useFormatter();
  const { platformModuleHelpers } = useContext(UserContext);

  const {
    selectedElements,
  } = useEntityToggle(localStorageKey);

  useEffect(() => {
    const newTargetEntities: TargetEntity[] = Object.values(selectedElements).map((item) => ({
      id: item.id,
      entity_type: item.entity_type ?? '',
      name: item.name ?? item.observable_value ?? '',
    }));
    setTargetEntities(newTargetEntities);
  }, [selectedElements]);

  const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable();
  const buildColumns = {
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
  const queryRef = useQueryLoading<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery>(
    stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    { ...searchPaginationOptions, count: 100 } as StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables,
  );

  const preloadedPaginationProps = {
    linesQuery: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    linesFragment: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery>;

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
      {queryRef && (
        <div style={{ height: '100%' }} ref={setTableRootRef}>
          <DataTable
            selectOnLineClick
            disableNavigation
            disableToolBar
            disableSelectAll
            rootRef={tableRootRef ?? undefined}
            variant={DataTableVariant.inline}
            dataColumns={buildColumns}
            resolvePath={(data: StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data) => data.stixCoreObjects?.edges?.map((n) => n?.node)}
            storageKey={localStorageKey}
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
                selectedEntities={targetEntities}
              />
            )]}
          />
        </div>
      )}
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
 * @param props.isReversable Whether this relationship can be reversed
 * @param props.defaultStartTime The default start time
 * @param props.defaultStopTime The default stop time
 * @returns JSX.Element
 */
const RenderForm = ({
  sourceEntity,
  targetEntities,
  handleClose,
  isReversable,
  defaultStartTime,
  defaultStopTime,
}: {
  sourceEntity: TargetEntity,
  targetEntities: TargetEntity[],
  handleClose: () => void,
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

  const relationshipTypes = resolvedRelationshipTypes;
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

interface StixCoreRelationshipCreationFromControlledDialContentProps {
  queryRef: PreloadedQuery<StixCoreRelationshipCreationFromEntityQuery>,
  entityId: string,
  isReversable?: boolean,
  defaultStartTime?: string,
  defaultStopTime?: string,
  controlledDial?: ({ onOpen }: { onOpen: () => void }) => React.ReactElement,
}

const StixCoreRelationshipCreationFromControlledDialContent: FunctionComponent<StixCoreRelationshipCreationFromControlledDialContentProps> = ({
  queryRef,
  entityId,
  isReversable = false,
  defaultStartTime,
  defaultStopTime,
  controlledDial,
}) => {
  const data = usePreloadedQuery<StixCoreRelationshipCreationFromEntityQuery>(stixCoreRelationshipCreationFromEntityQuery, queryRef);
  const [step, setStep] = useState(0);
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);

  const reset = () => {
    setStep(0);
    setTargetEntities([]);
  };

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
  const localStorageKey = `${entityId}_stixCoreRelationshipCreationFromEntity`;

  const [sortBy, setSortBy] = useState('_score');
  const [orderAsc, setOrderAsc] = useState(false);

  const { viewStorage, helpers } = usePaginationLocalStorage<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables>(
    localStorageKey,
    { filters: typeFilters },
  );
  const { searchTerm = '', orderAsc: storageOrderAsc, sortBy: storageSortBy, filters } = viewStorage;

  useEffect(() => {
    if (storageSortBy && (storageSortBy !== sortBy)) setSortBy(storageSortBy);
    if (storageOrderAsc !== undefined && (storageOrderAsc !== orderAsc)) setOrderAsc(storageOrderAsc);
  }, [storageOrderAsc, storageSortBy]);

  const contextFilters = useBuildEntityTypeBasedFilterContext(virtualEntityTypes, filters);
  const searchPaginationOptions: PaginationOptions = {
    search: searchTerm,
    filters: contextFilters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  } as PaginationOptions;

  if (!data.stixCoreObject) {
    throw Error('Can\'t resolve this entity');
  }
  const { name, entity_type, observable_value } = data.stixCoreObject;
  return (
    <Drawer
      title={''} // Defined in custom header prop
      controlledDial={controlledDial ?? CreateRelationshipControlledDial}
      onClose={reset}
      header={<CreateRelationshipHeader showCreates={step === 0} searchPaginationOptions={searchPaginationOptions} />}
      containerStyle={{
        minHeight: '100vh',
      }}
    >
      {({ onClose }) => (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          height: '100%',
        }}
        >
          {step === 0 && (
            <SelectEntity
              name={name ?? observable_value}
              entity_id={entityId}
              entity_type={entity_type}
              setTargetEntities={setTargetEntities}
              targetEntities={targetEntities}
              handleNextStep={() => setStep(1)}
              searchPaginationOptions={searchPaginationOptions}
              localStorageKey={localStorageKey}
              helpers={helpers}
              contextFilters={contextFilters}
              virtualEntityTypes={virtualEntityTypes}
            />
          )}
          {step === 1 && (
            <RenderForm
              sourceEntity={data.stixCoreObject as TargetEntity}
              targetEntities={targetEntities}
              handleClose={() => {
                reset();
                onClose();
              }}
              isReversable={isReversable}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
            />
          )}
        </div>
      )}
    </Drawer>
  );
};

export default StixCoreRelationshipCreationFromControlledDialContent;
