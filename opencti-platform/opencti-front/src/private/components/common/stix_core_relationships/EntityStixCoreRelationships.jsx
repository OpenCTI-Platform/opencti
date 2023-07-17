import React from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreRelationshipCreationFromEntity from './StixCoreRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import {
  convertFilters,
} from '../../../../utils/ListParameters';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import EntityStixCoreRelationshipsRelationshipsView from './EntityStixCoreRelationshipsRelationshipsView';
import EntityStixCoreRelationshipsEntitiesView from './EntityStixCoreRelationshipsEntitiesView';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';

const useStyles = makeStyles((theme) => ({
  bottomNav: {
    zIndex: 1000,
    padding: '10px 200px 10px 205px',
    display: 'flex',
  },
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing(1) / 4,
  },
}));

const EntityStixCoreRelationships = ({
  stixCoreObjectTypes,
  entityId,
  role,
  relationshipTypes,
  isRelationReversed,
  allDirections,
  defaultStartTime,
  defaultStopTime,
  currentView,
  paddingRightButtonAdd,
}) => {
/*
    let params = {};
    if (!props.noState) {
      params = buildViewParamsFromUrlAndStorage(
        props.history,
        props.location,
        `view-relationships-${props.entityId}-${props.stixCoreObjectTypes?.join(
          '-',
        )}-${props.relationshipTypes?.join('-')}`,
      );
    }
    state = {
      sortBy: R.propOr('created_at', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('entities', 'view', params),
      filters: R.propOr({}, 'filters', params),
    };
   */
  const classes = useStyles();
  const { viewStorage } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: {
        number: 0,
        symbol: '',
      },
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      filters: {},
    },
  );
  const {
    filters,
    searchTerm,
    sortBy,
    orderAsc,
  } = viewStorage;

  const finalView = currentView || view;
  let selectedTypes;
  if (filters.entity_type && filters.entity_type.length > 0) {
    if (filters.entity_type.filter((o) => o.id === 'all').length > 0) {
      selectedTypes = [];
    } else {
      selectedTypes = filters.entity_type.map((o) => o.id);
    }
  } else {
    selectedTypes = Array.isArray(stixCoreObjectTypes) && stixCoreObjectTypes.length > 0
      ? stixCoreObjectTypes
      : [];
  }
  let selectedRelationshipTypes;
  if (filters.relationship_type && filters.relationship_type.length > 0) {
    if (filters.relationship_type.filter((o) => o.id === 'all').length > 0) {
      selectedRelationshipTypes = [];
    } else {
      selectedRelationshipTypes = filters.relationship_type.map((o) => o.id);
    }
  } else {
    selectedRelationshipTypes = Array.isArray(relationshipTypes) && relationshipTypes.length > 0
      ? relationshipTypes
      : [];
  }
  let backgroundTaskFilters = filters;
  const finalFilters = convertFilters(
    R.omit(['relationship_type', 'entity_type'], filters),
  );
  let paginationOptions;
  if (finalView === 'entities') {
    paginationOptions = {
      types: selectedTypes,
      relationship_type: selectedRelationshipTypes,
      elementId: entityId,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
    };
    if (selectedRelationshipTypes.length > 0) {
      backgroundTaskFilters = {
        ...filters,
        entity_type:
            selectedTypes.length > 0
              ? selectedTypes.map((n) => ({ id: n, value: n }))
              : [{ id: 'Stix-Core-Object', value: 'Stix-Core-Object' }],
        [`rel_${selectedRelationshipTypes.at(0)}.*`]: [
          { id: entityId, value: entityId },
        ],
      };
    }
  } else {
    paginationOptions = {
      relationship_type: selectedRelationshipTypes,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
    };
    backgroundTaskFilters = {
      ...R.omit(['relationship_type', 'entity_type'], filters),
      entity_type:
          selectedRelationshipTypes.length > 0
            ? selectedRelationshipTypes.map((n) => ({ id: n, value: n }))
            : [
              {
                id: 'stix-core-relationship',
                value: 'stix-core-relationship',
              },
            ],
    };
    if (allDirections) {
      paginationOptions = {
        ...paginationOptions,
        elementId: entityId,
        elementWithTargetTypes: selectedTypes,
      };
      backgroundTaskFilters = {
        ...backgroundTaskFilters,
        elementId: [{ id: entityId, value: entityId }],
        elementWithTargetTypes:
            selectedTypes.length > 0
              ? selectedTypes.map((n) => ({ id: n, value: n }))
              : [{ id: 'Stix-Core-Object', value: 'Stix-Core-Object' }],
      };
    } else if (isRelationReversed) {
      paginationOptions = {
        ...paginationOptions,
        toId: entityId,
        toRole: role || null,
        fromTypes: selectedTypes,
      };
      backgroundTaskFilters = {
        ...backgroundTaskFilters,
        toId: [{ id: entityId, value: entityId }],
        fromTypes:
            selectedTypes.length > 0
              ? selectedTypes.map((n) => ({ id: n, value: n }))
              : [{ id: 'Stix-Core-Object', value: 'Stix-Core-Object' }],
      };
    } else {
      paginationOptions = {
        ...paginationOptions,
        fromId: entityId,
        fromRole: role || null,
        toTypes: selectedTypes,
      };
      backgroundTaskFilters = {
        ...backgroundTaskFilters,
        fromId: [{ id: entityId, value: entityId }],
        toTypes:
            selectedTypes.length > 0
              ? selectedTypes.map((n) => ({ id: n, value: n }))
              : [{ id: 'Stix-Core-Object', value: 'Stix-Core-Object' }],
      };
    }
  }
  const finalStixCoreObjectTypes = stixCoreObjectTypes || [
    'Stix-Core-Object',
  ];
  const paddingRight = paddingRightButtonAdd ?? 220;
  const targetStixCyberObservableTypes = finalStixCoreObjectTypes.includes('Stix-Core-Object')
      || finalStixCoreObjectTypes.includes('Stix-Cyber-Observable')
    ? ['Stix-Cyber-Observable']
    : null;
  const stixCoreObjectTypesWithoutObservables = finalStixCoreObjectTypes.filter((n) => n !== 'Stix-Cyber-Observable');
  const targetStixDomainObjectTypes = stixCoreObjectTypesWithoutObservables.includes('Stix-Core-Object')
    ? ['Stix-Domain-Object']
    : stixCoreObjectTypesWithoutObservables;
  return (
      <ExportContextProvider>
        <div className={classes.container}>
          {finalView === 'relationships'
            && <EntityStixCoreRelationshipsRelationshipsView
            entityId={entityId}
            backgroundTaskFilters={backgroundTaskFilters}
            stixCoreObjectTypes={stixCoreObjectTypes}
            relationshipTypes={relationshipTypes}
            entityLink={entityLink}
            isRelationReversed={isRelationReversed}
            allDirections={allDirections}
            disableExport={disableExport}
            currentView={currentView}
            enableNestedView={enableNestedView}
            />}
          {finalView === 'entities'
            && <EntityStixCoreRelationshipsEntitiesView
              backgroundTaskFilters={backgroundTaskFilters}
              stixCoreObjectTypes={stixCoreObjectTypes}
              relationshipTypes={relationshipTypes}
              entityLink={entityLink}
              isRelationReversed={isRelationReversed}
              disableExport={disableExport}
              currentView={currentView}
              enableNestedView={enableNestedView}
            />}
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <StixCoreRelationshipCreationFromEntity
              entityId={entityId}
              isRelationReversed={isRelationReversed}
              paddingRight={paddingRight}
              targetStixDomainObjectTypes={targetStixDomainObjectTypes}
              targetStixCyberObservableTypes={targetStixCyberObservableTypes}
              allowedRelationshipTypes={relationshipTypes}
              paginationOptions={paginationOptions}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              connectionKey={
                finalView === 'entities'
                  ? 'Pagination_stixCoreObjects'
                  : undefined
              }
            />
          </Security>
        </div>
      </ExportContextProvider>
  );
};

EntityStixCoreRelationships.propTypes = {
  entityId: PropTypes.string,
  role: PropTypes.string,
  stixCoreObjectTypes: PropTypes.array,
  relationshipTypes: PropTypes.array,
  entityLink: PropTypes.string,
  exploreLink: PropTypes.string,
  isRelationReversed: PropTypes.bool,
  allDirections: PropTypes.bool,
  noState: PropTypes.bool,
  disableExport: PropTypes.bool,
  currentView: PropTypes.string,
  enableNestedView: PropTypes.func,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
  paddingRightButtonAdd: PropTypes.string,
};

export default EntityStixCoreRelationships;
