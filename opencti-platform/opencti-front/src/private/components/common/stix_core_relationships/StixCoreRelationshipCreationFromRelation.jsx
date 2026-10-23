import React, { useState } from 'react';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import CircularProgress from '@mui/material/CircularProgress';
import { Stack } from '@mui/material';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { formatDate } from '../../../../utils/Time';
import { insertNode } from '../../../../utils/store';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import {
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
} from './StixCoreRelationshipCreationFromEntity';
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

// Own component so that the entities are only queried once the drawer shows the list
const StixCoreRelationshipCreationFromRelationSelectEntity = ({
  storageKey,
  initialValues,
  dataColumns,
  searchPaginationOptions,
  contextFilters,
  targetTypes,
  setNumberOfElements,
  createButton,
  onSelect,
}) => {
  const [tableRootRef, setTableRootRef] = useState(null);
  const queryRef = useQueryLoading(
    stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    { ...searchPaginationOptions, count: 25 },
  );
  return (
    <div style={{ flex: '1 0 0', overflow: 'hidden' }} ref={setTableRootRef}>
      {queryRef && (
        <DataTable
          disableToolBar
          disableNavigation
          disableLineSelection
          hideSavedFilters
          variant={DataTableVariant.inline}
          rootRef={tableRootRef ?? undefined}
          dataColumns={dataColumns}
          resolvePath={(data) => data.stixCoreObjects?.edges?.map((n) => n?.node)}
          storageKey={storageKey}
          lineFragment={stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment}
          initialValues={initialValues}
          contextFilters={contextFilters}
          preloadedPaginationProps={{
            linesQuery: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
            linesFragment: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
            queryRef,
            nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
            setNumberOfElements,
          }}
          entityTypes={targetTypes}
          availableEntityTypes={targetTypes}
          createButton={createButton}
          onLineClick={onSelect}
        />
      )}
    </div>
  );
};

const StixCoreRelationshipCreationFromRelation = ({
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
  const [targetEntity, setTargetEntity] = useState(null);
  const [openCreateEntity, setOpenCreateEntity] = useState(false);
  const [openCreateObservable, setOpenCreateObservable] = useState(false);

  // Same listing as the 'Add entities' panel (ContainerAddStixCoreObjectsInLine)
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
  const { viewStorage, helpers } = usePaginationLocalStorage(
    storageKey,
    initialValues,
    true,
  );
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
  };
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

  const handleClose = () => {
    setStep(0);
    setTargetEntity(null);
    setOpen(false);
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
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
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc(
        'externalReferences',
        R.pluck('value', values.externalReferences),
      ),
    )(values);
    commitMutation({
      mutation: isRelationReversed
        ? stixCoreRelationshipCreationFromRelationToMutation
        : stixCoreRelationshipCreationFromRelationFromMutation,
      variables: { input: finalValues },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_stixCoreRelationships',
          paginationOptions,
          'stixCoreRelationshipAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };

  const handleResetSelection = () => {
    setStep(0);
    setTargetEntity(null);
  };

  const handleSelectEntity = (stixCoreObject) => {
    setStep(1);
    setTargetEntity(stixCoreObject);
  };

  // Mounted in the drawer header, as in the 'Add entities' panel, and opened by the buttons of the list
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
      onSelect={handleSelectEntity}
    />
  );

  const renderForm = (sourceEntity) => {
    let fromEntity = sourceEntity;
    let toEntity = targetEntity;
    if (isRelationReversed) {
      fromEntity = targetEntity;
      toEntity = sourceEntity;
    }

    return (
      <UserContext.Consumer>
        {({ schema }) => {
          const relationshipTypes = R.uniq(resolveRelationsTypes(
            fromEntity.parent_types.includes('Stix-Cyber-Observable')
              ? 'observable'
              : fromEntity.entity_type,
            toEntity.entity_type,
            schema.schemaRelationsTypesMapping,
          ).filter(
            (n) => R.isNil(allowedRelationshipTypes)
              || allowedRelationshipTypes.length === 0
              || allowedRelationshipTypes.includes(n),
          ));
          return (
            <StixCoreRelationshipCreationForm
              fromEntities={[fromEntity]}
              toEntities={[toEntity]}
              relationshipTypes={relationshipTypes}
              handleResetSelection={handleResetSelection}
              onSubmit={onSubmit}
              handleClose={handleClose}
            />
          );
        }}
      </UserContext.Consumer>
    );
  };

  const renderLoader = () => (
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
        <QueryRenderer
          query={stixCoreRelationshipCreationFromRelationQuery}
          variables={{ id: entityId }}
          render={({ props }) => {
            if (props && props.stixCoreRelationship) {
              if (step === 0) {
                return renderSelectEntity();
              }
              return (
                <div style={{ marginTop: -20 }}>
                  {renderForm(props.stixCoreRelationship)}
                </div>
              );
            }
            return renderLoader();
          }}
        />
      </Drawer>
    </div>
  );
};

export default StixCoreRelationshipCreationFromRelation;
