import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, PreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import ListLines from '../../../../../components/list_lines/ListLines';
import { PaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import useAuth from '../../../../../utils/hooks/useAuth';
import useEntityToggle from '../../../../../utils/hooks/useEntityToggle';
import EntityStixCoreRelationshipsContextualViewLines from './EntityStixCoreRelationshipsContextualViewLines';
import { useFormatter } from '../../../../../components/i18n';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import StixCoreObjectLabels from '../../stix_core_objects/StixCoreObjectLabels';
import ItemMarkings from '../../../../../components/ItemMarkings';
import { DataColumns, PaginationOptions } from '../../../../../components/list_lines';
import ToolBar from '../../../data/ToolBar';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import usePreloadedFragment from '../../../../../utils/hooks/usePreloadedFragment';
import { isNotEmptyField } from '../../../../../utils/utils';
import { EntityStixCoreRelationshipsContextualViewQuery } from './__generated__/EntityStixCoreRelationshipsContextualViewQuery.graphql';
import { EntityStixCoreRelationshipsContextualViewFragment_stixDomainObject$key } from './__generated__/EntityStixCoreRelationshipsContextualViewFragment_stixDomainObject.graphql';
import { EntityStixCoreRelationshipsContextualViewLinesQuery$variables } from './__generated__/EntityStixCoreRelationshipsContextualViewLinesQuery.graphql';
import { EntityStixCoreRelationshipsContextualViewLine_node$data } from './__generated__/EntityStixCoreRelationshipsContextualViewLine_node.graphql';
import { isStixCoreObjects, isStixCyberObservables } from '../../../../../utils/stixTypeUtils';
import type { Theme } from '../../../../../components/Theme';
import { resolveLink } from '../../../../../utils/Entity';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';
import ItemEntityType from '../../../../../components/ItemEntityType';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  chip: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: 4,
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
    },
  },
}));

const contextualViewFragment = graphql`
  fragment EntityStixCoreRelationshipsContextualViewFragment_stixDomainObject on StixDomainObject
  @argumentDefinitions(entityTypes: { type: "[String!]" } ) {
    containers(entityTypes: $entityTypes) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

const contextualViewQuery = graphql`
  query EntityStixCoreRelationshipsContextualViewQuery($id: String!, $entityTypes: [String!]) {
    stixDomainObject(id: $id) {
      ...EntityStixCoreRelationshipsContextualViewFragment_stixDomainObject @arguments(entityTypes: $entityTypes)
    }
  }
`;

interface EntityStixCoreRelationshipsContextualViewProps {
  queryRef: PreloadedQuery<EntityStixCoreRelationshipsContextualViewQuery>;
  entityId: string;
  localStorage: PaginationLocalStorage<PaginationOptions>;
  relationshipTypes: string[];
  stixCoreObjectTypes: string[];
  currentView: string;
}

const EntityStixCoreRelationshipsContextualViewComponent: FunctionComponent<EntityStixCoreRelationshipsContextualViewProps> = ({
  queryRef,
  entityId,
  localStorage,
  relationshipTypes = [],
  stixCoreObjectTypes = [],
  currentView,
}) => {
  const classes = useStyles();
  const { t_i18n, n, nsdt } = useFormatter();

  const stixDomainObject = usePreloadedFragment<
    EntityStixCoreRelationshipsContextualViewQuery,
    EntityStixCoreRelationshipsContextualViewFragment_stixDomainObject$key
  >({
    queryDef: contextualViewQuery,
    fragmentDef: contextualViewFragment,
    queryRef,
    nodePath: 'stixDomainObject',
  });

  const { viewStorage, helpers, localStorageKey } = localStorage;

  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
  } = viewStorage;

  const availableFilterKeys = [
    'relationship_type',
    'objectMarking',
    'confidence',
    'objectLabel',
    'createdBy',
    'creator_id',
    'created',
    'containers',
  ];

  const { platformModuleHelpers } = useAuth();
  const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
  const isObservables = isStixCyberObservables(stixCoreObjectTypes);
  const dataColumns: DataColumns = {
    entity_type: {
      label: 'Type',
      width: '10%',
      isSortable: true,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => (
        <ItemEntityType entityType={stixCoreObject.entity_type} />
      ),
    },
    [isObservables ? 'observable_value' : 'name']: {
      label: isObservables ? 'Value' : 'Name',
      width: '20%',

      isSortable: isStixCoreObjects(stixCoreObjectTypes)
        ? false
        : isObservables
          ? isRuntimeSort
          : true,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => getMainRepresentative(stixCoreObject),
    },
    createdBy: {
      label: 'Author',
      width: '10%',
      isSortable: isRuntimeSort ?? false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => stixCoreObject.createdBy?.name ?? '-',
    },
    creator: {
      label: 'Creators',
      width: '10%',
      isSortable: isRuntimeSort ?? false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => (stixCoreObject.creators ?? []).map((c) => c?.name).join(', '),
    },
    objectLabel: {
      label: 'Labels',
      width: '15%',
      isSortable: false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => (
        <StixCoreObjectLabels
          variant="inList"
          labels={stixCoreObject.objectLabel}
          onClick={helpers.handleAddFilter}
        />
      ),
    },
    created_at: {
      label: 'Platform creation date',
      width: '15%',
      isSortable: true,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => nsdt(stixCoreObject.created_at),
    },
    objectMarking: {
      label: 'Marking',
      width: '10%',
      isSortable: isRuntimeSort ?? false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => (
        <ItemMarkings
          variant="inList"
          markingDefinitions={stixCoreObject.objectMarking ?? []}
          limit={1}
        />
      ),
    },
    cases_and_analysis: {
      label: 'Cases & Analyses',
      width: '10%',
      isSortable: false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => {
        const link = `${resolveLink(stixCoreObject.entity_type)}/${stixCoreObject.id}`;
        const linkAnalyses = `${link}/analyses`;
        return (
          <Chip
            classes={{ root: classes.chip }}
            label={n(stixCoreObject.containers?.edges?.length)}
            component={Link}
            to={linkAnalyses}
          />
        );
      },
    },
  };

  const containers = stixDomainObject.containers?.edges?.map((e) => e?.node)
    .filter((r) => isNotEmptyField(r)) as { id: string }[] ?? [];

  const existEntitiesToDisplay = containers.length > 0;

  // Filters due to screen context
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, stixCoreObjectTypes);

  // if no containers, the query should return nothing
  // (and the filter is not valid (empty array not authorized with the 'eq' operator))
  // so we won't use it and won't do the query: components are not called if !existEntitiesToDisplay
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'entity_type', operator: 'eq', mode: 'or', values: stixCoreObjectTypes },
      { key: 'objects', operator: 'eq', mode: 'or', values: containers.map((r) => r.id) },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const paginationOptions = {
    search: searchTerm,
    orderBy: (sortBy && (sortBy in dataColumns) && dataColumns[sortBy].isSortable) ? sortBy : 'entity_type',
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: contextFilters,
  } as unknown as EntityStixCoreRelationshipsContextualViewLinesQuery$variables; // Because of FilterMode

  const {
    selectedElements,
    numberOfSelectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>(localStorageKey);

  return (
    <>
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        handleChangeView={helpers.handleChangeView}
        handleToggleSelectAll={handleToggleSelectAll}
        paginationOptions={paginationOptions}
        selectAll={selectAll}
        keyword={searchTerm}
        displayImport={true}
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportContext={{ entity_id: entityId, entity_type: 'Stix-Core-Object' }}
        iconExtension={true}
        filters={filters}
        availableFilterKeys={availableFilterKeys}
        availableRelationshipTypes={relationshipTypes}
        availableEntityTypes={stixCoreObjectTypes}
        numberOfElements={numberOfElements}
        noPadding={true}
        disableCards={true}
        enableEntitiesView={true}
        enableContextualView={true}
        currentView={currentView}
        searchContext={{ elementId: [entityId] }}
      >
        {
          existEntitiesToDisplay
          && (
            <EntityStixCoreRelationshipsContextualViewLines
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              onToggleEntity={onToggleEntity}
              setNumberOfElements={helpers.handleSetNumberOfElements}
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              selectAll={selectAll}
            />
          )
        }
      </ListLines>
      {existEntitiesToDisplay
        && (
          <ToolBar
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            numberOfSelectedElements={numberOfSelectedElements}
            selectAll={selectAll}
            filters={contextFilters}
            search={searchTerm}
            handleClearSelectedElements={handleClearSelectedElements}
            variant="medium"
            warning={true}
            warningMessage={t_i18n(
              'Be careful, you are about to delete the selected entities',
            )}
          />
        )}
    </>
  );
};

const EntityStixCoreRelationshipsContextualView: FunctionComponent<Omit<EntityStixCoreRelationshipsContextualViewProps, 'queryRef'>> = (props) => {
  const queryRef = useQueryLoading<EntityStixCoreRelationshipsContextualViewQuery>(
    contextualViewQuery,
    { id: props.entityId, entityTypes: ['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'] },
  );

  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityStixCoreRelationshipsContextualViewComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityStixCoreRelationshipsContextualView;
