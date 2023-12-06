import React, { FunctionComponent, useEffect, useContext, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import IconButton from '@mui/material/IconButton';
import { Add, ChevronRightOutlined } from '@mui/icons-material';
import Fab from '@mui/material/Fab';
import CircularProgress from '@mui/material/CircularProgress';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import makeStyles from '@mui/styles/makeStyles';
import { StixCoreRelationshipCreationFromEntityQuery$data } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$data,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import { Option } from '@components/common/form/ReferenceField';
import { Button } from '@mui/material';
import { commitMutation, handleErrorInForm, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { formatDate } from '../../../../utils/Time';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import { isNodeInConnection } from '../../../../utils/store';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import { useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import StixCoreRelationshipCreationFromEntityStixCoreObjectsLines, {
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
} from './StixCoreRelationshipCreationFromEntityStixCoreObjectsLines';
import { ModuleHelper } from '../../../../utils/platformModulesHelper';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import Drawer from '../drawer/Drawer';
import { RelateComponentContext } from '../menus/RelateComponentProvider';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1001,
  },
  container: {
    height: '100%',
    width: '100%',
  },
  continue: {
    position: 'fixed',
    bottom: 40,
    right: 30,
    zIndex: 1001,
  },
}));

export const stixCoreRelationshipCreationFromEntityQuery = graphql`
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

const stixCoreRelationshipCreationFromEntityFromMutation = graphql`
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
  paginationOptions: unknown;
  connectionKey?: string;
  paddingRight: number;
  variant?: string;
  targetEntities?: TargetEntity[];
  onCreate?: () => void;
  openExports?: boolean;
  handleReverseRelation?: () => void;
  controlledDial?: (({ onOpen, onClose }: {
    onOpen: () => void;
    onClose: () => void;
  }) => React.ReactElement<unknown, string | React.JSXElementConstructor<unknown>>)
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
}
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
    controlledDial = undefined,
  } = props;
  const {
    relationshipTypes: initialRelationshipTypes,
    filters,
    helpers,
  } = useContext(RelateComponentContext);
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
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);
  const [createAnother, setCreateAnother] = useState(false);
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
  const [numberOfElements, setNumberOfElements] = useState({
    number: 0,
    symbol: '',
  });
  const [searchTerm, setSearchTerm] = useState('');
  const containerRef = useRef(null);

  const handleClose = () => {
    setOpen(createAnother);
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
            const fromOrTo = isRelationReversed ? 'from' : 'to';

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
    const results = Promise.all(targetEntities.map(async (targetEntity) => {
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
      return commit(finalValues)
        .catch((error) => handleErrorInForm(error, setErrors));
    }));
    results
      .then(() => {
        MESSAGING$.notifySuccess(`${t_i18n('Relationships successfully created')}: ${targetEntities.length}`);
      })
      .catch((error) => {
        MESSAGING$.notifyError(error);
      })
      .finally(() => {
        setSubmitting(false);
        resetForm();
        handleClose();
        if (typeof onCreate === 'function') {
          onCreate();
        }
      });
  };

  const handleResetSelection = () => {
    setStep(0);
    setTargetEntities([]);
  };

  const handleSort = (field: string, sortOrderAsc: boolean) => {
    setSortBy(field);
    setOrderAsc(sortOrderAsc);
  };

  const handleNextStep = () => {
    setStep(1);
  };

  const {
    onToggleEntity,
    selectedElements,
    deSelectedElements,
  } = useEntityToggle(`${entityId}_stixCoreRelationshipCreationFromEntity`);

  const onInstanceToggleEntity = (entity: TargetEntity) => {
    onToggleEntity(entity);
    if (entity.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([entity.id], selectedElements);
      setTargetEntities(R.values(newSelectedElements));
    } else {
      const newSelectedElements = R.assoc(
        entity.id,
        entity,
        selectedElements || {},
      );
      setTargetEntities(R.values(newSelectedElements));
    }
  };

  const buildColumns = (platformModuleHelpers: ModuleHelper | undefined) => {
    const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable();
    return {
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
  };
  const searchPaginationOptions = {
    search: searchTerm,
    filters: useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, virtualEntityTypes),
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  };

  const renderSelectEntity = () => {
    return (
      <div data-testid="stixCoreRelationshipCreationFromEntity-component">
        <div className={classes.container}>
          <div style={{ float: 'right', marginTop: '-60px', display: 'flex' }}>
            {!isOnlySCOs && (
              <StixDomainObjectCreation
                display={open}
                inputValue={searchTerm}
                paginationKey="Pagination_stixCoreObjects"
                paginationOptions={searchPaginationOptions}
                stixDomainObjectTypes={actualTypeFilterValues}
                controlledDial={({ onOpen }: { onOpen: () => void; }) => (
                  <Button
                    variant='outlined'
                    style={{ marginRight: '5px' }}
                    onClick={onOpen}
                    disableElevation
                  >
                    {t_i18n('Create Entity')} <Add />
                  </Button>
                )}
                creationCallback={undefined}
                confidence={undefined}
                defaultCreatedBy={undefined}
                defaultMarkingDefinitions={undefined}
                open={undefined}
                speeddial={undefined}
                handleClose={undefined}
              />
            )}
            {!isOnlySDOs && (
              <StixCyberObservableCreation
                display={open}
                contextual={true}
                inputValue={searchTerm}
                paginationKey="Pagination_stixCoreObjects"
                paginationOptions={searchPaginationOptions}
                controlledDial={({ onOpen }: { onOpen: () => void; }) => (
                  <Button
                    variant='outlined'
                    onClick={onOpen}
                    disableElevation
                  >
                    {t_i18n('Create Observable')} <Add />
                  </Button>
                )}
                open={undefined}
                handleClose={undefined}
                type={undefined}
                speeddial={undefined}
              />
            )}
          </div>
          <UserContext.Consumer>
            {({ platformModuleHelpers }) => (
              <ListLines
                sortBy={sortBy}
                orderAsc={orderAsc}
                dataColumns={buildColumns(platformModuleHelpers)}
                handleSearch={setSearchTerm}
                keyword={searchTerm}
                handleSort={handleSort}
                helpers={helpers}
                disableCards={true}
                filters={filters}
                disableExport={true}
                paginationOptions={searchPaginationOptions}
                numberOfElements={numberOfElements}
                iconExtension={true}
                parametersWithPadding={true}
                availableEntityTypes={virtualEntityTypes}
                handleToggleSelectAll="no"
                entityTypes={virtualEntityTypes}
                additionalFilterKeys={{
                  filterKeys: ['entity_type'],
                  filtersRestrictions: { preventRemoveFor: ['entity_type'], preventLocalModeSwitchingFor: ['entity_type'], preventEditionFor: ['entity_type'] } }
                  }
              >
                <QueryRenderer
                  query={stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery}
                  variables={{ count: 100, ...searchPaginationOptions }}
                  render={({ props: renderProps }: { props: StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$data }) => (
                    <StixCoreRelationshipCreationFromEntityStixCoreObjectsLines
                      data={renderProps}
                      paginationOptions={paginationOptions}
                      dataColumns={buildColumns(platformModuleHelpers)}
                      initialLoading={renderProps === null}
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
            )}
          </UserContext.Consumer>
          <Fab
            variant='extended'
            disabled={targetEntities.length < 1}
            size='small'
            color='secondary'
            onClick={() => handleNextStep()}
            className={classes.continue}
            sx={{
              borderRadius: '4px',
            }}
          >
            {t_i18n('Continue')}
            <ChevronRightOutlined />
          </Fab>
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
          const relationshipTypes = initialRelationshipTypes.length > 0
            ? initialRelationshipTypes
            : R.uniq(R.filter(
              (n) => R.isNil(allowedRelationshipTypes)
            || allowedRelationshipTypes.length === 0
            || allowedRelationshipTypes.includes('stix-core-relationship')
            || allowedRelationshipTypes.includes(n),
              resolveRelationsTypes(
                fromEntities[0].entity_type,
                toEntities[0].entity_type,
                schema?.schemaRelationsTypesMapping ?? new Map(),
              ),
            ));
          return (
            <StixCoreRelationshipCreationForm
              fromEntities={fromEntities}
              toEntities={toEntities}
              relationshipTypes={relationshipTypes}
              handleReverseRelation={handleReverseRelation}
              handleResetSelection={handleResetSelection}
              onSubmit={onSubmit}
              createAnother={setCreateAnother}
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
          <CircularProgress size={80} thickness={2}/>
        </span>
      </div>
    );
  };

  let openElement = controlledDial
    ? controlledDial({
      onOpen: () => setOpen(true),
      onClose: handleClose,
    })
    : '';
  if (variant === 'inLine') {
    openElement = (
      <IconButton
        color="primary"
        aria-label="Label"
        onClick={() => setOpen(true)}
        style={{ float: 'left', margin: '-15px 0 0 -2px' }}
        size="large"
      >
        <Add fontSize="small"/>
      </IconButton>
    );
  } else if (controlledDial === undefined && !openExports) {
    openElement = (
      <Fab
        onClick={() => setOpen(true)}
        color="primary"
        aria-label="Add"
        className={classes.createButton}
        style={{ right: paddingRight || 30 }}
      >
        <Add/>
      </Fab>
    );
  }

  return (
    <>
      {openElement}
      <Drawer
        title={'Create a relationship'}
        open={open}
        onClose={handleClose}
      >
        <QueryRenderer
          query={stixCoreRelationshipCreationFromEntityQuery}
          variables={{ id: entityId }}
          render={({ props: renderProps }: ({ props: StixCoreRelationshipCreationFromEntityQuery$data })) => {
            if (renderProps?.stixCoreObject) {
              return (
                <div style={{ minHeight: '100%' }}>
                  {step === 0 ? renderSelectEntity() : ''}
                  {step === 1 ? renderForm(renderProps.stixCoreObject) : ''}
                </div>
              );
            }
            return renderLoader();
          }}
        />
      </Drawer>
    </>
  );
};

export default StixCoreRelationshipCreationFromEntity;
