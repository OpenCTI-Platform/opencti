import React, { useEffect, useRef, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import { v4 as uuid } from 'uuid';
import { graphql, usePreloadedQuery } from 'react-relay';
import * as R from 'ramda';
import * as Yup from 'yup';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import MenuItem from '@mui/material/MenuItem';
import { Add, ArrowRightAlt, ChevronRightOutlined, Close } from '@mui/icons-material';
import Fab from '@mui/material/Fab';
import CircularProgress from '@mui/material/CircularProgress';
import { ConnectionHandler } from 'relay-runtime';
import SpeedDial from '@mui/material/SpeedDial';
import SpeedDialIcon from '@mui/material/SpeedDialIcon';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import { GlobeModel, HexagonOutline } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { minutesBefore, now, parse } from '../../../../utils/Time';
import ItemIcon from '../../../../components/ItemIcon';
import SelectField from '../../../../components/fields/SelectField';
import StixNestedRefRelationCreationFromEntityLines, { stixNestedRefRelationshipCreationFromEntityLinesQuery } from './StixNestedRefRelationshipCreationFromEntityLines';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import { truncate } from '../../../../utils/String';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ListLines from '../../../../components/list_lines/ListLines';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { emptyFilterGroup, removeIdFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
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
  container: {
    padding: '15px 0 0 15px',
    height: '100%',
    width: '100%',
  },
  containerRelation: {
    padding: '10px 20px 20px 20px',
  },
  item: {
    position: 'absolute',
    width: 180,
    height: 80,
    borderRadius: 10,
  },
  itemHeader: {
    padding: '10px 0 10px 0',
  },
  icon: {
    position: 'absolute',
    top: 8,
    left: 5,
    fontSize: 8,
  },
  type: {
    width: '100%',
    textAlign: 'center',
    color: theme.palette.text.primary,
    fontSize: 11,
  },
  content: {
    width: '100%',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: theme.palette.text.primary,
    textAlign: 'center',
  },
  name: {
    display: 'inline-block',
    lineHeight: 1,
    fontSize: 12,
    verticalAlign: 'middle',
  },
  relation: {
    position: 'relative',
    height: 100,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
    padding: 10,
    marginBottom: 10,
  },
  continue: {
    position: 'fixed',
    bottom: 40,
    right: 30,
    zIndex: 1001,
  },
  relationCreate: {
    position: 'relative',
    height: 100,
  },
  middle: {
    margin: '0 auto',
    width: 200,
    textAlign: 'center',
    padding: 0,
    color: theme.palette.text.primary,
  },
  buttonBack: {
    marginTop: 20,
    textAlign: 'left',
    float: 'left',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
    float: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  speedDial: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  speedDialButton: {
    backgroundColor: theme.palette.primary.main,
    color: theme.palette.primary.contrastText,
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
    },
  },
}));

const stixNestedRefRelationshipResolveTypes = graphql`
  query StixNestedRefRelationshipCreationFromEntityResolveQuery($id: String!, $toType: String!) {
    stixSchemaRefRelationships(id: $id, toType: $toType) {
      entity {
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
        description
      }
      ... on Campaign {
        name
        description
      }
      ... on CourseOfAction {
        name
        description
      }
      ... on Individual {
        name
        description
      }
      ... on Organization {
        name
        description
      }
      ... on Sector {
        name
        description
      }
      ... on System {
        name
        description
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
        description
      }
      ... on Position {
        name
        description
      }
      ... on City {
        name
        description
      }
      ... on Country {
        name
        description
      }
      ... on Region {
        name
        description
      }
      ... on Malware {
        name
        description
      }
      ... on ThreatActor {
        name
        description
      }
      ... on Tool {
        name
        description
      }
      ... on Vulnerability {
        name
        description
      }
      ... on Incident {
        name
        description
      }
      ... on DataComponent {
        name
        entity_type
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
      from
      to
    }
  }
`;

const stixNestedRefRelationshipCreationFromEntityMutation = graphql`
  mutation StixNestedRefRelationshipCreationFromEntityMutation(
    $input: StixRefRelationshipAddInput!
  ) {
    stixRefRelationshipAdd(input: $input) {
      id
      relationship_type
      start_time
      stop_time
      from {
        ... on StixCyberObservable {
          id
          entity_type
          observable_value
          created_at
          updated_at
        }
      }
      to {
        ... on StixCyberObservable {
          id
          entity_type
          observable_value
          created_at
          updated_at
        }
      }
    }
  }
`;

export const stixNestedRefRelationResolveTypes = graphql`
  query StixNestedRefRelationshipCreationFromEntityPossibleTypesQuery($type: String!) {
    stixSchemaRefRelationshipsPossibleTypes(type: $type)
  }
`;

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_stixNestedRefRelationships',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const StixNestedRefRelationshipCreationFromEntity = ({
  possibleTypesQueryRef,
  entityId,
  entityType,
  paginationOptions,
  variant,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const [open, setOpen] = useState(false);
  const [openSpeedDial, setOpenSpeedDial] = useState(false);
  const [openCreateEntity, setOpenCreateEntity] = useState(false);
  const [openCreateObservable, setOpenCreateObservable] = useState(false);
  const [step, setStep] = useState(0);
  const [targetEntities, setTargetEntities] = useState([]);
  const [sortBy, setSortBy] = useState('_score');
  const [orderAsc, setOrderAsc] = useState(false);
  const [numberOfElements, setNumberOfElements] = useState({
    number: 0,
    symbol: '',
  });
  const [searchTerm, setSearchTerm] = useState('');
  const containerRef = useRef(null);

  const { stixSchemaRefRelationshipsPossibleTypes: targetStixCoreObjectTypes } = usePreloadedQuery(stixNestedRefRelationResolveTypes, possibleTypesQueryRef);

  const actualTypeFilter = [
    ...(targetStixCoreObjectTypes ?? []),
  ];
  const initialFilters = actualTypeFilter.length > 0
    ? {
      mode: 'and',
      filterGroups: [],
      filters: [{
        id: uuid(),
        key: 'entity_type',
        values: actualTypeFilter,
        operator: 'eq',
        mode: 'or',
      }],
    }
    : emptyFilterGroup;
  const [filters, helpers] = useFiltersState(initialFilters, initialFilters);
  const virtualEntityTypes = actualTypeFilter.length > 0 ? actualTypeFilter : ['Stix-Domain-Object', 'Stix-Cyber-Observable'];
  const stixNestedRefRelationshipValidation = () => Yup.object().shape({
    relationship_type: Yup.string().required(t_i18n('This field is required')),
    start_time: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t_i18n('This field is required')),
    stop_time: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t_i18n('This field is required')),
  });

  const {
    onToggleEntity,
    setSelectedElements,
    selectedElements,
    deSelectedElements,
  } = useEntityToggle(`${entityId}_stixNestedRefRelationshipCreationFromEntity`);

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

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setSearchTerm('');
    setStep(0);
    setOpen(false);
    setSelectedElements({});
    setTargetEntities([]);
  };

  const commit = (finalValues) => {
    return new Promise((resolve) => {
      commitMutation({
        mutation: stixNestedRefRelationshipCreationFromEntityMutation,
        variables: {
          input: finalValues,
        },
        updater: (store) => {
          const payload = store.getRootField('stixRefRelationshipAdd');
          const newEdge = payload.setLinkedRecord(payload, 'node');
          const container = store.getRoot();
          sharedUpdater(
            store,
            container.getDataID(),
            paginationOptions,
            newEdge,
          );
        },
        onCompleted: (response) => {
          resolve(response);
        },
      });
    });
  };

  const onSubmit = async (values, { setSubmitting, resetForm }, isReversedRelation) => {
    setSubmitting(true);

    for (const targetEntity of targetEntities) {
      const fromEntityId = isReversedRelation
        ? targetEntity.id
        : entityId;
      const toEntityId = isReversedRelation
        ? entityId
        : targetEntity.id;
      const finalValues = {
        ...values,
        fromId: fromEntityId,
        toId: toEntityId,
        start_time: parse(values.start_time).format(),
        stop_time: parse(values.stop_time).format(),
      };
      try {
        // eslint-disable-next-line no-await-in-loop
        await commit(finalValues);
      } catch (_error) {
        setSubmitting(false);
      }
      setSubmitting(false);
      resetForm();
      handleClose();
    }
  };

  const handleResetSelection = () => setStep(0);

  const handleSort = (field, sortOrderAsc) => {
    setSortBy(field);
    setOrderAsc(sortOrderAsc);
  };

  const handleNextStep = () => {
    setStep(1);
  };

  const handleSelectEntity = (stixDomainObject) => {
    setStep(1);
    setTargetEntities(stixDomainObject);
  };

  const onInstanceToggleEntity = (entity) => {
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

  useEffect(() => {
    setSortBy('created_at');
    setOrderAsc(false);
  }, [searchTerm]);

  const renderSelectEntity = () => {
    const searchPaginationOptions = {
      search: searchTerm,
      filters: removeIdFromFilterGroupObject(filters),
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      types: targetStixCoreObjectTypes,
    };
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
        isSortable: false,
      },
      objectLabel: {
        label: 'Labels',
        width: '22%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        width: '15%',
        isSortable: false,
      },
    };
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t_i18n('Create a relationship')}
          </Typography>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={dataColumns}
              keyword={searchTerm}
              helpers={helpers}
              disableCards={true}
              handleSearch={setSearchTerm}
              filters={filters}
              disableExport={true}
              handleSort={handleSort}
              numberOfElements={numberOfElements}
              paginationOptions={searchPaginationOptions}
              iconExtension={true}
              parametersWithPadding={true}
              handleToggleSelectAll="no"
              entityTypes={virtualEntityTypes}
              availableEntityTypes={virtualEntityTypes}
              additionalFilterKeys={{
                filterKeys: ['entity_type'],
                filtersRestrictions: { preventFilterValuesEditionFor: new Map([['entity_type', actualTypeFilter]]) } }
              }
            >
              <QueryRenderer
                query={stixNestedRefRelationshipCreationFromEntityLinesQuery}
                variables={{ count: 25, ...searchPaginationOptions }}
                render={({ props }) => {
                  if (props) {
                    return (
                      <StixNestedRefRelationCreationFromEntityLines
                        entityType={entityType}
                        handleSelect={handleSelectEntity}
                        data={props}
                        dataColumns={dataColumns}
                        initialLoading={false}
                        setNumberOfElements={setNumberOfElements}
                        onToggleEntity={onInstanceToggleEntity}
                        containerRef={containerRef}
                        selectedElements={selectedElements}
                        deSelectedElements={deSelectedElements}
                        selectAll={false}
                      />
                    );
                  } return (<></>);
                }}
              />
            </ListLines>
          </>
          {targetEntities.length === 0 && (
            <>
              <SpeedDial
                className={classes.createButton}
                ariaLabel="Create"
                icon={<SpeedDialIcon />}
                onClose={handleCloseSpeedDial}
                onOpen={handleOpenSpeedDial}
                open={openSpeedDial}
                FabProps={{
                  color: 'secondary',
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
                stixCyberObservableTypes={targetStixCoreObjectTypes}
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
              {t_i18n('Continue')}
              <ChevronRightOutlined/>
            </Fab>
          )}
        </div>
      </div>
    );
  };

  const renderForm = (resolveEntityRef) => {
    let fromEntity = resolveEntityRef.entity;
    let toEntities = targetEntities;
    const isSameEntityType = toEntities.every((item) => item.entity_type === toEntities[0].entity_type);
    const isMultipleTo = toEntities.length > 1;

    let relationshipTypes = [];
    const isReversedRelation = resolveEntityRef.from.length === 0 && resolveEntityRef.to.length !== 0;

    if (isReversedRelation) {
      fromEntity = targetEntities;
      toEntities = resolveEntityRef.entity;
      relationshipTypes = resolveEntityRef.to;
    } else {
      relationshipTypes = resolveEntityRef.from;
    }

    // This condition is to avoid to use relation that would did not work with some kind of entity type
    // nested objects with different entity type will soon be implemented
    if (!isSameEntityType) relationshipTypes = [];
    const defaultRelationshipType = relationshipTypes[0];

    const defaultTime = now();
    const initialValues = {
      relationship_type: defaultRelationshipType,
      start_time: minutesBefore(1, defaultTime),
      stop_time: defaultTime,
    };

    const fromEntityType = isReversedRelation ? fromEntity[0]?.entity_type : fromEntity?.entity_type;
    const toEntityType = isReversedRelation ? toEntities?.entity_type : toEntities[0]?.entity_type;

    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={stixNestedRefRelationshipValidation}
        onSubmit={(values, formikHelpers) => onSubmit(values, formikHelpers, isReversedRelation)}
        onReset={handleClose}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form>
            <div className={classes.header}>
              <IconButton
                aria-label="Close"
                className={classes.closeButton}
                onClick={handleClose}
                size="large"
              >
                <Close fontSize="small" color="primary" />
              </IconButton>
              <Typography variant="h6">{t_i18n('Create a relationship')}</Typography>
            </div>
            <div className={classes.containerRelation}>
              <div className={classes.relationCreate}>
                <div
                  className={classes.item}
                  style={{
                    border: `2px solid ${itemColor(fromEntityType)}`,
                    top: 10,
                    left: 0,
                  }}
                >
                  <div
                    className={classes.itemHeader}
                    style={{
                      borderBottom: `1px solid ${itemColor(
                        fromEntityType,
                      )}`,
                    }}
                  >
                    <div className={classes.icon}>
                      <ItemIcon
                        type={fromEntityType}
                        color={itemColor(fromEntityType)}
                        size="small"
                      />
                    </div>
                    <div className={classes.type}>
                      {t_i18n(`entity_${fromEntityType}`)}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {truncate(getMainRepresentative(isReversedRelation ? fromEntity[0] : fromEntity), 20)}
                    </span>
                  </div>
                </div>
                <div className={classes.middle} style={{ paddingTop: 25 }}>
                  <ArrowRightAlt fontSize="large" />
                </div>
                <div
                  className={classes.item}
                  style={{
                    border: `2px solid ${itemColor(toEntityType)}`,
                    top: 10,
                    right: 0,
                  }}
                >
                  <div
                    className={classes.itemHeader}
                    style={{
                      borderBottom: `1px solid ${itemColor(
                        toEntityType,
                      )}`,
                    }}
                  >
                    <div className={classes.icon}>
                      <ItemIcon
                        type={toEntityType}
                        color={itemColor(toEntityType)}
                        size="small"
                      />
                    </div>
                    <div className={classes.type}>
                      {t_i18n(`entity_${toEntityType}`)}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {isMultipleTo
                        ? (<em>{t_i18n('Multiple entities selected')}</em>)
                        : (truncate(getMainRepresentative(isReversedRelation ? toEntities : toEntities[0]), 20))
                      }
                    </span>
                  </div>
                </div>
              </div>
              <Field
                component={SelectField}
                variant="standard"
                name="relationship_type"
                label={t_i18n('Relationship type')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
              >
                {R.map(
                  (type) => (
                    <MenuItem key={type} value={type}>
                      {t_i18n(`relationship_${type}`)}
                    </MenuItem>
                  ),
                  relationshipTypes,
                )}
              </Field>
              <Field
                component={DateTimePickerField}
                name="start_time"
                textFieldProps={{
                  label: t_i18n('Start time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <Field
                component={DateTimePickerField}
                name="stop_time"
                textFieldProps={{
                  label: t_i18n('Stop time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <div className={classes.buttonBack}>
                <Button
                  variant="contained"
                  onClick={handleResetSelection}
                  disabled={isSubmitting}
                >
                  {t_i18n('Back')}
                </Button>
              </div>
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </div>
          </Form>
        )}
      </Formik>
    );
  };

  // eslint-disable-next-line
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
      {variant === 'inLine' ? (
        <IconButton
          color="primary"
          aria-label="Label"
          onClick={handleOpen}
          style={{ float: 'left', margin: '-15px 0 0 -2px', zIndex: 1 }}
          size="large"
        >
          <Add fontSize="small" />
        </IconButton>
      ) : (
        <Fab
          onClick={handleOpen}
          color="primary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
      )}
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <>
          {step === 0
            ? renderSelectEntity()
            : null
          }
          {step === 1
            ? <QueryRenderer
                query={stixNestedRefRelationshipResolveTypes}
                variables={{
                  id: entityId,
                  toType: targetEntities[0].entity_type,
                }}
                render={({ props }) => {
                  if (props && props.stixSchemaRefRelationships) {
                    return (
                      <div>
                        {renderForm(props.stixSchemaRefRelationships)}
                      </div>
                    );
                  }
                  return renderLoader();
                }}
              />
            : null
          }
        </>
      </Drawer>
    </>
  );
};

export default StixNestedRefRelationshipCreationFromEntity;
