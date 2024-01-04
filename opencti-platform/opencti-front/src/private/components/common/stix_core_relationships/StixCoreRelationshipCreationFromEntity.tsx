import React, { FunctionComponent, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Add, ChevronRightOutlined, Close } from '@mui/icons-material';
import Fab from '@mui/material/Fab';
import CircularProgress from '@mui/material/CircularProgress';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import makeStyles from '@mui/styles/makeStyles';
import SpeedDial from '@mui/material/SpeedDial';
import SpeedDialIcon from '@mui/material/SpeedDialIcon';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import { GlobeModel, HexagonOutline } from 'mdi-material-ui';
import { StixCoreRelationshipCreationFromEntityQuery$data } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import {
  StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$data,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import { Option } from '@components/common/form/ReferenceField';
import { commitMutation, handleErrorInForm, QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { formatDate } from '../../../../utils/Time';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import { isNodeInConnection } from '../../../../utils/store';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import { emptyFilterGroup, removeIdFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import StixCoreRelationshipCreationFromEntityStixCoreObjectsLines, {
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
} from './StixCoreRelationshipCreationFromEntityStixCoreObjectsLines';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { Theme } from '../../../../components/Theme';
import { ModuleHelper } from '../../../../utils/platformModulesHelper';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1001,
  },
  title: {
    float: 'left',
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  continue: {
    position: 'fixed',
    bottom: 40,
    right: 30,
    zIndex: 1001,
  },
  container: {
    padding: '15px 0 0 15px',
    height: '100%',
    width: '100%',
  },
  speedDialButton: {
    backgroundColor: theme.palette.secondary.main,
    color: '#ffffff',
    '&:hover': {
      backgroundColor: theme.palette.secondary.main,
    },
  },
}));

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
  allowedRelationshipTypes: string[];
  isRelationReversed?: boolean;
  targetStixDomainObjectTypes: string[];
  targetStixCyberObservableTypes: string[];
  defaultStartTime: string;
  defaultStopTime: string;
  paginationOptions: unknown;
  connectionKey: string;
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
interface TargetEntity {
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
  } = props;
  let isOnlySDOs = false;
  let isOnlySCOs = false;
  let actualTypeFilter = [
    ...(targetStixDomainObjectTypes ?? []),
    ...(targetStixCyberObservableTypes ?? []),
  ];
  let virtualTypeFilter = ['Stix-Domain-Object', 'Stix-Cyber-Observable'];
  if (
    (targetStixDomainObjectTypes ?? []).length > 0
        && (targetStixCyberObservableTypes ?? []).length === 0
  ) {
    isOnlySDOs = true;
    virtualTypeFilter = targetStixDomainObjectTypes;
    if (!targetStixDomainObjectTypes.includes('Stix-Domain-Object')) {
      actualTypeFilter = targetStixDomainObjectTypes;
    }
  } else if (
    (targetStixCyberObservableTypes ?? []).length > 0
        && (targetStixDomainObjectTypes ?? []).length === 0
  ) {
    isOnlySCOs = true;
    virtualTypeFilter = targetStixCyberObservableTypes;
    if (!targetStixDomainObjectTypes.includes('Stix-Cyber-Observable')) {
      actualTypeFilter = targetStixCyberObservableTypes;
    }
  } else if (
    (targetStixCyberObservableTypes ?? []).length > 0
        && (targetStixDomainObjectTypes ?? []).length > 0
  ) {
    virtualTypeFilter = [
      ...targetStixDomainObjectTypes,
      ...targetStixCyberObservableTypes,
    ];
  }
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const [openSpeedDial, setOpenSpeedDial] = useState(false);
  const [openCreateEntity, setOpenCreateEntity] = useState(false);
  const [openCreateObservable, setOpenCreateObservable] = useState(false);
  const [step, setStep] = useState(0);
  const [targetEntities, setTargetEntities] = useState(
    targetEntitiesProps ?? [],
  );
  const [selectedElements, setSelectedElements] = useState({});
  const [sortBy, setSortBy] = useState('_score');
  const [orderAsc, setOrderAsc] = useState(false);
  const [filters, helpers] = useFiltersState(
    actualTypeFilter.length > 0
      ? {
        mode: 'and',
        filterGroups: [],
        filters: [{
          key: 'entity_type',
          values: actualTypeFilter,
          operator: 'eq',
          mode: 'or',
        }],
      }
      : emptyFilterGroup,
  );
  const [numberOfElements, setNumberOfElements] = useState({
    number: 0,
    symbol: '',
  });
  const [searchTerm, setSearchTerm] = useState('');
  const containerRef = useRef(null);

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
                && !isNodeInConnection(payload.getLinkedRecord(isRelationReversed ? 'from' : 'to'), conn)
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

  const handleSort = (field: string, sortOrderAsc: boolean) => {
    setSortBy(field);
    setOrderAsc(sortOrderAsc);
  };

  const handleNextStep = () => {
    setStep(1);
  };

  const onToggleEntity = (entity: TargetEntity) => {
    if (entity.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([entity.id], selectedElements);
      setSelectedElements(newSelectedElements);
      setTargetEntities(R.values(newSelectedElements));
    } else {
      const newSelectedElements = R.assoc(
        entity.id,
        entity,
        selectedElements || {},
      );
      setSelectedElements(newSelectedElements);
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

  const renderSelectEntity = () => {
    const searchPaginationOptions = {
      search: searchTerm,
      filters: removeIdFromFilterGroupObject(filters),
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={() => handleClose()}
            size="large"
          >
            <Close fontSize="small" color="primary"/>
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Create a relationship')}
          </Typography>
          <div className="clearfix"/>
        </div>
        <div className={classes.container}>
          <UserContext.Consumer>
            {({ platformModuleHelpers }) => (
              <>
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
                  availableEntityTypes={virtualTypeFilter}
                  handleToggleSelectAll="no"
                  availableFilterKeys={[
                    'entity_type',
                    'objectMarking',
                    'objectLabel',
                    'createdBy',
                    'confidence',
                    'x_opencti_organization_type',
                    'created',
                    'created_at',
                    'creator_id',
                  ]}
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
                        deSelectedElements={{}}
                        selectAll={false}
                        onToggleEntity={onToggleEntity}
                      />
                    )}
                  />
                </ListLines>
              </>
            )}
          </UserContext.Consumer>
          {targetEntities.length === 0 && isOnlySDOs && (
          <StixDomainObjectCreation
            display={open}
            inputValue={searchTerm}
            paginationKey="Pagination_stixCoreObjects"
            paginationOptions={searchPaginationOptions}
            stixDomainObjectTypes={actualTypeFilter}
            creationCallback={undefined}
            confidence={undefined}
            defaultCreatedBy={undefined}
            defaultMarkingDefinitions={undefined}
            open={undefined}
            speeddial={undefined}
            handleClose={undefined}
          />
          )}
          {targetEntities.length === 0 && isOnlySCOs && (
          <StixCyberObservableCreation
            display={open}
            contextual={true}
            inputValue={searchTerm}
            paginationKey="Pagination_stixCoreObjects"
            paginationOptions={searchPaginationOptions}
            open={undefined}
            handleClose={undefined}
            type={undefined}
            speeddial={undefined}
          />
          )}
          {targetEntities.length === 0 && !isOnlySDOs && !isOnlySCOs && (
          <>
            <SpeedDial
              className={classes.createButton}
              ariaLabel="Create"
              icon={<SpeedDialIcon/>}
              onClose={handleCloseSpeedDial}
              onOpen={handleOpenSpeedDial}
              open={openSpeedDial}
              FabProps={{
                color: 'secondary',
              }}
            >
              <SpeedDialAction
                title={t('Create an observable')}
                icon={<HexagonOutline/>}
                tooltipTitle={t('Create an observable')}
                onClick={handleOpenCreateObservable}
                FabProps={{
                  classes: { root: classes.speedDialButton },
                }}
              />
              <SpeedDialAction
                title={t('Create an entity')}
                icon={<GlobeModel/>}
                tooltipTitle={t('Create an entity')}
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
              creationCallback={undefined}
              confidence={undefined}
              defaultCreatedBy={undefined}
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
              type={undefined}
            />
          </>
          )}
          {targetEntities.length > 0 && (
          <Fab
            variant="extended"
            className={classes.continue}
            size="small"
            color="secondary"
            onClick={() => handleNextStep()}
          >
            {t('Continue')}
            <ChevronRightOutlined/>
          </Fab>
          )}
        </div>
      </>
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
          const relationshipTypes = R.uniq(R.filter(
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
            <>
              <div className={classes.header}>
                <IconButton
                  aria-label="Close"
                  className={classes.closeButton}
                  onClick={() => handleClose()}
                  size="large"
                >
                  <Close fontSize="small" color="primary"/>
                </IconButton>
                <Typography variant="h6">
                  {t('Create a relationship')}
                </Typography>
              </div>
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
            </>
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

  return (
    <>
      {/* eslint-disable-next-line no-nested-ternary */}
      {variant === 'inLine' ? (
        <IconButton
          color="secondary"
          aria-label="Label"
          onClick={() => setOpen(true)}
          style={{ float: 'left', margin: '-15px 0 0 -2px' }}
          size="large"
        >
          <Add fontSize="small"/>
        </IconButton>
      ) : !openExports ? (
        <Fab
          onClick={() => setOpen(true)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
          style={{ right: paddingRight || 30 }}
        >
          <Add/>
        </Fab>
      ) : (
        ''
      )}
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
        SlideProps={{
          // containerRef is forwarded to ListLinesContent so it listens to scroll events and load data with an InfiniteLoader
          // we must target the element inside the Drawer that holds the scrolling = the Slide
          ref: containerRef,
        }}
      >
        <QueryRenderer
          query={stixCoreRelationshipCreationFromEntityQuery}
          variables={{ id: entityId }}
          render={({ props: renderProps }: ({ props: StixCoreRelationshipCreationFromEntityQuery$data })) => {
            if (renderProps && renderProps.stixCoreObject) {
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
