import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import { ChevronRightOutlined } from '@mui/icons-material';
import { Fab } from '@mui/material';
import { v4 as uuid } from 'uuid';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik';
import { PaginationOptions } from '../../../../components/list_lines';
import Drawer from '../drawer/Drawer';
import CreateRelationshipControlledDial from '../stix_core_relationships/CreateRelationshipControlledDial';
import CreateRelationshipHeader from '../stix_core_relationships/CreateRelationshipHeader';
import { TargetEntity } from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import Loader from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import {
  stixNestedRefRelationshipCreationFromEntityLinesFragment,
  stixNestedRefRelationshipCreationFromEntityLinesQuery,
} from './StixNestedRefRelationshipCreationFromEntityLines';
import {
  StixNestedRefRelationshipCreationFromEntityLinesQuery,
  StixNestedRefRelationshipCreationFromEntityLinesQuery$variables,
} from './__generated__/StixNestedRefRelationshipCreationFromEntityLinesQuery.graphql';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { StixNestedRefRelationshipCreationFromEntityLines_data$data } from './__generated__/StixNestedRefRelationshipCreationFromEntityLines_data.graphql';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { stixNestedRefRelationshipCreationFromEntityLineFragment } from './StixNestedRefRelationshipCreationFromEntityLine';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { UseLocalStorageHelpers, usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../../components/i18n';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import StixNestedRefRelationshipCreationForm, { StixNestedRefRelationshipCreationFormValues } from './StixNestedRefRelationshipCreationForm';
import { StixNestedRefRelationshipCreationFromEntityResolveQuery$data } from './__generated__/StixNestedRefRelationshipCreationFromEntityResolveQuery.graphql';
import { CreateRelationshipContext } from '../menus/CreateRelationshipContextProvider';
import { commitMutation, handleErrorInForm, QueryRenderer } from '../../../../relay/environment';
import { formatDate } from '../../../../utils/Time';
import { stixNestedRefRelationshipCreationFromEntityMutation, stixNestedRefRelationshipResolveTypes } from './StixNestedRefRelationshipCreationFromEntity';

interface SelectEntityProps {
  setTargetEntities: React.Dispatch<TargetEntity[]>,
  searchPaginationOptions: PaginationOptions,
  localStorageKey: string,
  helpers: UseLocalStorageHelpers,
  handleNextStep: () => void,
  types: string[],
}

const SelectEntity: FunctionComponent<SelectEntityProps> = ({
  setTargetEntities,
  searchPaginationOptions,
  localStorageKey,
  helpers,
  handleNextStep,
  types,
}) => {
  const { t_i18n } = useFormatter();
  const dataColumns = {
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
      isSortable: false,
    },
    objectLabel: {
      label: 'Labels',
      percentWidth: 22,
      isSortable: false,
    },
    objectMarking: {
      label: 'Marking',
      percentWidth: 16,
      isSortable: false,
    },
  };
  const queryRef = useQueryLoading(
    stixNestedRefRelationshipCreationFromEntityLinesQuery,
    { ...searchPaginationOptions, count: 100 } as StixNestedRefRelationshipCreationFromEntityLinesQuery$variables,
  );

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

  const preloadedPaginationProps = {
    linesQuery: stixNestedRefRelationshipCreationFromEntityLinesQuery,
    linesFragment: stixNestedRefRelationshipCreationFromEntityLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixNestedRefRelationshipCreationFromEntityLinesQuery>;

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
      style={{
        height: '100%',
        width: '100%',
      }}
    >
      {!queryRef && (<Loader />)}
      {queryRef && (
        <div style={{ height: '100%' }} ref={setTableRootRef}>
          <DataTable
            selectOnLineClick
            disableNavigation
            disableToolBar
            disableSelectAll
            rootRef={tableRootRef ?? undefined}
            variant={DataTableVariant.default}
            dataColumns={dataColumns}
            resolvePath={(data: StixNestedRefRelationshipCreationFromEntityLines_data$data) => data.stixCoreObjects?.edges?.map((n) => n?.node)}
            storageKey={localStorageKey}
            lineFragment={stixNestedRefRelationshipCreationFromEntityLineFragment}
            initialValues={initialValues}
            preloadedPaginationProps={preloadedPaginationProps}
            availableEntityTypes={types}
            entityTypes={types}
          />
        </div>
      )}
      <Fab
        variant="extended"
        size="small"
        color="primary"
        onClick={() => handleNextStep()}
        disabled={Object.values(selectedElements).length < 1}
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

interface RenderFormProps {
  data: StixNestedRefRelationshipCreationFromEntityResolveQuery$data,
  targetEntities: TargetEntity[],
  handleClose: () => void,
  handleBack: () => void,
  isReversable?: boolean
  defaultStartTime?: string,
  defaultStopTime?: string,
}

const RenderForm: FunctionComponent<RenderFormProps> = ({
  data,
  targetEntities,
  handleClose,
  handleBack,
  isReversable,
  defaultStartTime,
  defaultStopTime,
}) => {
  if (data?.stixSchemaRefRelationships === null || data?.stixSchemaRefRelationships === undefined) return <></>;
  const { state: {
    reversed: initiallyReversed,
    onCreate,
    paginationOptions,
  } } = useContext(CreateRelationshipContext);
  const [reversed, setReversed] = useState<boolean>(initiallyReversed ?? false);

  const handleReverse = () => setReversed(!reversed);

  const sourceEntity = data.stixSchemaRefRelationships.entity as TargetEntity;
  let fromEntities = [sourceEntity];
  let toEntities = targetEntities;
  if (reversed) {
    fromEntities = targetEntities;
    toEntities = [sourceEntity];
  }
  let relationshipTypes: string[] = [];
  if ((!data.stixSchemaRefRelationships.from
    || data.stixSchemaRefRelationships.from.length === 0)
    && (!data.stixSchemaRefRelationships.to
      || data.stixSchemaRefRelationships.to.length !== 0)) {
    if (reversed) {
      relationshipTypes = data.stixSchemaRefRelationships.to as string[] ?? [];
    }
  } else {
    relationshipTypes = data.stixSchemaRefRelationships.from as string[] ?? [];
  }
  const startTime = defaultStartTime ?? (new Date()).toISOString();
  const stopTime = defaultStopTime ?? (new Date()).toISOString();

  const commit = (finalValues: object) => {
    return new Promise((resolve, reject) => {
      commitMutation({
        mutation: stixNestedRefRelationshipCreationFromEntityMutation,
        variables: { input: finalValues },
        updater: (store: RecordSourceSelectorProxy) => {
          if (typeof onCreate !== 'function') {
            const payload = store.getRootField('stixRefRelationshipAdd');
            const container = store.getRoot();
            const userProxy = store.get(container.getDataID());
            if (userProxy != null && payload != null && paginationOptions != null) {
              const newEdge = payload.setLinkedRecord(payload, 'node');
              const conn = ConnectionHandler.getConnection(
                userProxy,
                'Pagination_stixNestedRefRelationships',
                paginationOptions,
              );
              if (conn != null) {
                ConnectionHandler.insertEdgeBefore(conn, newEdge);
              }
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

  const onSubmit: FormikConfig<StixNestedRefRelationshipCreationFormValues>['onSubmit'] = async (values, { setSubmitting, setErrors, resetForm }) => {
    setSubmitting(true);
    for (const targetEntity of targetEntities) {
      const fromEntityId = reversed ? targetEntity.id : sourceEntity.id;
      const toEntityId = reversed ? sourceEntity.id : targetEntity.id;
      const finalValues = {
        fromId: fromEntityId,
        toId: toEntityId,
        relationship_type: values.relationship_type,
        start_time: formatDate(values.start_time),
        stop_time: formatDate(values.stop_time),
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
    <StixNestedRefRelationshipCreationForm
      sourceEntity={fromEntities[0]}
      targetEntities={toEntities}
      relationshipTypes={relationshipTypes}
      defaultStartTime={startTime}
      defaultStopTime={stopTime}
      onSubmit={onSubmit}
      handleClose={handleClose}
      handleBack={handleBack}
      handleReverse={isReversable ? handleReverse : undefined}
    />
  );
};

interface StixNestedRefRelationshipCreationFromEntityFablessProps {
  id: string,
  targetStixCoreObjectTypes: string[],
  controlledDial?: ({ onOpen }: { onOpen: () => void }) => React.ReactElement,
}

const StixNestedRefRelationshipCreationFromEntityFabless: FunctionComponent<
StixNestedRefRelationshipCreationFromEntityFablessProps
> = ({
  id,
  targetStixCoreObjectTypes = [],
  controlledDial,
}) => {
  const [step, setStep] = useState<number>(0);
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);

  const reset = () => {
    setStep(0);
    setTargetEntities([]);
  };

  const typeFilters = targetStixCoreObjectTypes.length > 0
    ? {
      mode: 'and',
      filterGroups: [],
      filters: [{
        id: uuid(),
        key: 'entity_type',
        values: targetStixCoreObjectTypes,
        operator: 'eq',
        mode: 'or',
      }],
    }
    : emptyFilterGroup;

  const localStorageKey = `${id}_stixNestedRefRelationshipCreationFromEntity`;

  const [sortBy, setSortBy] = useState('_score');
  const [orderAsc, setOrderAsc] = useState(false);

  const { viewStorage, helpers } = usePaginationLocalStorage<StixNestedRefRelationshipCreationFromEntityLinesQuery$variables>(
    localStorageKey,
    { filters: typeFilters },
  );
  const { searchTerm = '', orderAsc: storageOrderAsc, sortBy: storageSortBy, filters } = viewStorage;

  useEffect(() => {
    if (storageSortBy && (storageSortBy !== sortBy)) setSortBy(storageSortBy);
    if (storageOrderAsc !== undefined && (storageOrderAsc !== orderAsc)) setOrderAsc(storageOrderAsc);
  }, [storageOrderAsc, storageSortBy]);

  const contextFilters = useBuildEntityTypeBasedFilterContext(targetStixCoreObjectTypes, filters);
  const searchPaginationOptions: PaginationOptions = {
    search: searchTerm,
    filters: contextFilters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  } as PaginationOptions;

  return (
    <Drawer
      title={''} // Defined in custom header prop
      controlledDial={controlledDial ?? CreateRelationshipControlledDial}
      onClose={reset}
      header={(
        <CreateRelationshipHeader
          showCreates={step === 0}
          searchPaginationOptions={searchPaginationOptions}
        />
      )}
      containerStyle={{
        minHeight: '100vh',
        position: 'fixed',
        top: '60px',
        width: '50%',
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
              setTargetEntities={setTargetEntities}
              handleNextStep={() => setStep(1)}
              searchPaginationOptions={searchPaginationOptions}
              localStorageKey={localStorageKey}
              helpers={helpers}
              types={targetStixCoreObjectTypes}
            />
          )}
          {step === 1 && (
            <QueryRenderer
              query={stixNestedRefRelationshipResolveTypes}
              variables={{
                id,
                toType: targetEntities[0].entity_type,
              }}
              render={({ props }: { props: StixNestedRefRelationshipCreationFromEntityResolveQuery$data }) => {
                if (props && props.stixSchemaRefRelationships) {
                  return (
                    <div>
                      {/* {renderForm(props.stixSchemaRefRelationships)} */}
                      <RenderForm
                        data={props}
                        targetEntities={targetEntities}
                        handleClose={() => {
                          reset();
                          onClose();
                        }}
                        handleBack={() => setStep(0)}
                      />
                    </div>
                  );
                }
                return (<Loader />);
              }}
            />
          )}
        </div>
      )}
    </Drawer>
  );
};

export default StixNestedRefRelationshipCreationFromEntityFabless;
