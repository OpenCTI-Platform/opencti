import React, { FunctionComponent, useContext, useRef, useState } from 'react';
import { v4 as uuid } from 'uuid';
import { useFormatter } from 'src/components/i18n';
import { Button, CircularProgress, Fab, Typography } from '@mui/material';
import { Add, ChevronRightOutlined } from '@mui/icons-material';
import { QueryRenderer, commitMutation, handleErrorInForm } from 'src/relay/environment';
import { UserContext } from 'src/utils/hooks/useAuth';
import ListLines from 'src/components/list_lines/ListLines';
import { emptyFilterGroup, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from 'src/utils/filters/filtersUtils';
import useFiltersState from 'src/utils/filters/useFiltersState';
import useEntityToggle from 'src/utils/hooks/useEntityToggle';
import { resolveRelationsTypes } from 'src/utils/Relation';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import { isNodeInConnection } from 'src/utils/store';
import { FormikConfig } from 'formik';
import { formatDate } from 'src/utils/Time';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes } from 'src/utils/stixTypeUtils';
import StixCyberObservableCreation from '@components/observations/stix_cyber_observables/StixCyberObservableCreation';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { CreateRelationshipContext } from '../menus/CreateRelationshipContextProvider';
import StixCoreRelationshipCreationFromEntityStixCoreObjectsLines, {
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
} from './StixCoreRelationshipCreationFromEntityStixCoreObjectsLines';
import { StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$data } from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import {
  StixCoreRelationshipCreationFromEntityForm,
  TargetEntity,
  stixCoreRelationshipCreationFromEntityFromMutation,
  stixCoreRelationshipCreationFromEntityQuery,
  stixCoreRelationshipCreationFromEntityToMutation,
} from './StixCoreRelationshipCreationFromEntity';
import { StixCoreRelationshipCreationFromEntityQuery$data } from './__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import Drawer from '../drawer/Drawer';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

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
      {t_i18n('Create Relationship')} <Add />
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
    filters: useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, entityTypes),
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
              variant='contained'
              disableElevation
              size='small'
              aria-label={t_i18n('Create an entity')}
              style={{
                marginLeft: '3px',
                marginRight: showSCOCreation ? undefined : '15px',
                fontSize: 'small',
              }}
            >
              {t_i18n('Create an entity')} <Add />
            </Button>
          )}
          {showSCOCreation && (
            <Button
              onClick={handleOpenCreateObservable}
              variant='contained'
              disableElevation
              size='small'
              aria-label={t_i18n('Create an observable')}
              style={{
                marginLeft: '3px',
                marginRight: '15px',
                fontSize: 'small',
              }}
            >
              {t_i18n('Create an observable')} <Add />
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
 * @param props.id The source entity's id
 * @param props.setTargetEntities Dispatch to set relationship target entities
 * @param props.handleNextStep Function to continue on to the next step
 * @returns JSX.Element
 */
const SelectEntity = ({
  id,
  setTargetEntities,
  handleNextStep,
}: {
  id: string,
  setTargetEntities: React.Dispatch<TargetEntity[]>,
  handleNextStep: () => void,
}) => {
  const { t_i18n } = useFormatter();
  const { state: { stixCoreObjectTypes } } = useContext(CreateRelationshipContext);
  const { platformModuleHelpers } = useContext(UserContext);
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
  const [filters, helpers] = useFiltersState(typeFilters, typeFilters);
  const virtualEntityTypes = ['Stix-Domain-Object', 'Stix-Cyber-Observable'];
  const [sortBy, setSortBy] = useState<string>('_score');
  const [orderAsc, setOrderAsc] = useState<boolean>(false);
  const [numberOfElements, setNumberOfElements] = useState({
    number: 0,
    symbol: '',
  });
  const [searchTerm, setSearchTerm] = useState<string>('');
  const containerRef = useRef(null);
  const {
    onToggleEntity,
    selectedElements,
    deSelectedElements,
  } = useEntityToggle<TargetEntity>(`${id}_stixCoreRelationshipCreationFromEntity`);
  const onInstanceToggleEntity = (entity: TargetEntity) => {
    onToggleEntity(entity);
    if (entity.id in (selectedElements || {})) {
      const newSelectedElements = { ...selectedElements };
      delete newSelectedElements[entity.id];
      setTargetEntities(Object.values(newSelectedElements));
    } else {
      setTargetEntities(Object.values({
        [entity.id]: entity,
        ...(selectedElements ?? {}),
      }));
    }
  };
  const searchPaginationOptions = {
    search: searchTerm,
    filters: useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, virtualEntityTypes),
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  };
  const handleSort = (field: string, sortOrderAsc: boolean) => {
    setSortBy(field);
    setOrderAsc(sortOrderAsc);
  };
  const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable();
  const dataColumns = {
    entity_type: {
      label: 'Type',
      width: '15%',
      isSortable: true,
    },
    value: {
      label: 'Value',
      width: '32%',
      isSortable: false,
    },
    createdBy: {
      label: 'Author',
      width: '15%',
      isSortable: isRuntimeSort,
    },
    objectLabel: {
      label: 'Labels',
      width: '22%',
      isSortable: false,
    },
    objectMarking: {
      label: 'Marking',
      width: '15%',
      isSortable: isRuntimeSort,
    },
  };
  return (
    <div
      data-testid="stixCoreRelationshipCreationFromEntity-component"
      style={{
        height: '100%',
        width: '100%',
      }}
    >
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        numberOfElements={numberOfElements}
        paginationOptions={searchPaginationOptions}
        filters={filters}
        helpers={helpers}
        keyword={searchTerm}
        handleSearch={setSearchTerm}
        handleSort={handleSort}
        dataColumns={dataColumns}
        disableCards={true}
        disableExport={true}
        iconExtension={true}
        parametersWithPadding={true}
        handleToggleSelectAll="no"
        entityTypes={virtualEntityTypes}
        availableEntityTypes={virtualEntityTypes}
        additionalFilterKeys={{
          filterKeys: ['entity_type'],
          filtersRestrictions: { preventRemoveFor: ['entity_type'], preventLocalModeSwitchingFor: ['entity_type'], preventEditionFor: ['entity_type'] } }
        }
      >
        <QueryRenderer
          query={stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery}
          variables={{ count: 100, ...searchPaginationOptions }}
          render={({ props }: { props: StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$data }) => (
            <StixCoreRelationshipCreationFromEntityStixCoreObjectsLines
              data={props}
              paginationOptions={searchPaginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              setNumberOfElements={setNumberOfElements}
              containerRef={containerRef}
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              selectAll={false}
              onToggleEntity={onInstanceToggleEntity}
            />
          )}
        />
      </ListLines>
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
    >
      <QueryRenderer
        query={stixCoreRelationshipCreationFromEntityQuery}
        variables={{ id }}
        render={({ props }: { props: StixCoreRelationshipCreationFromEntityQuery$data }) => {
          if (props?.stixCoreObject) {
            return <div style={{ minHeight: '100%' }}>
              {step === 0 && (
                <SelectEntity
                  id={id}
                  setTargetEntities={setTargetEntities}
                  handleNextStep={() => setStep(1)}
                />
              )}
              {step === 1 && (
                <RenderForm
                  sourceEntity={props.stixCoreObject}
                  targetEntities={targetEntities}
                  handleClose={reset}
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
    </Drawer>
  );
};

export default StixCoreRelationshipCreationFromControlledDial;
