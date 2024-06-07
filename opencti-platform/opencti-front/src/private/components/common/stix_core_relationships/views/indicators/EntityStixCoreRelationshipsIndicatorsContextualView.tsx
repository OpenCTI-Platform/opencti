import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import {
  EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery$variables,
} from '@components/common/stix_core_relationships/views/indicators/__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery.graphql';
import ItemPatternType from '../../../../../../components/ItemPatternType';
import EntityStixCoreRelationshipsIndicatorsContextualViewLines from './EntityStixCoreRelationshipsIndicatorsContextualViewLines';
import { DataColumns, PaginationOptions } from '../../../../../../components/list_lines';
import { isNotEmptyField } from '../../../../../../utils/utils';
import { EntityStixCoreRelationshipsIndicatorsContextualViewQuery } from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewQuery.graphql';
import { PaginationLocalStorage } from '../../../../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../../../../components/i18n';
import usePreloadedFragment from '../../../../../../utils/hooks/usePreloadedFragment';
import {
  EntityStixCoreRelationshipsIndicatorsContextualViewFragment_stixDomainObject$key,
} from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewFragment_stixDomainObject.graphql';
import useEntityToggle from '../../../../../../utils/hooks/useEntityToggle';
import { EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data } from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewLine_node.graphql';
import useAuth from '../../../../../../utils/hooks/useAuth';
import { getMainRepresentative } from '../../../../../../utils/defaultRepresentatives';
import StixCoreObjectLabels from '../../../stix_core_objects/StixCoreObjectLabels';
import ItemMarkings from '../../../../../../components/ItemMarkings';
import ListLines from '../../../../../../components/list_lines/ListLines';
import Loader, { LoaderVariant } from '../../../../../../components/Loader';
import ToolBar from '../../../../data/ToolBar';
import useQueryLoading from '../../../../../../utils/hooks/useQueryLoading';
import { EntityStixCoreRelationshipsContextualViewLine_node$data } from '../__generated__/EntityStixCoreRelationshipsContextualViewLine_node.graphql';
import { resolveLink } from '../../../../../../utils/Entity';
import type { Theme } from '../../../../../../components/Theme';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../../../utils/filters/filtersHelpers-types';

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
  fragment EntityStixCoreRelationshipsIndicatorsContextualViewFragment_stixDomainObject on StixDomainObject
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
  query EntityStixCoreRelationshipsIndicatorsContextualViewQuery($id: String!, $entityTypes: [String!]) {
    stixDomainObject(id: $id) {
      ...EntityStixCoreRelationshipsIndicatorsContextualViewFragment_stixDomainObject @arguments(entityTypes: $entityTypes)
    }
  }
`;

interface EntityStixCoreRelationshipsIndicatorsContextualViewProps {
  queryRef: PreloadedQuery<EntityStixCoreRelationshipsIndicatorsContextualViewQuery>
  entityId: string
  localStorage: PaginationLocalStorage<PaginationOptions>
  relationshipTypes: string[]
  stixCoreObjectTypes: string[]
  currentView: string
}

const EntityStixCoreRelationshipsIndicatorsContextualViewComponent: FunctionComponent<EntityStixCoreRelationshipsIndicatorsContextualViewProps> = ({
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
  EntityStixCoreRelationshipsIndicatorsContextualViewQuery,
  EntityStixCoreRelationshipsIndicatorsContextualViewFragment_stixDomainObject$key
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
  } = viewStorage;

  const availableFilterKeys = [
    'objectLabel',
    'objectMarking',
    'created',
    'created',
    'valid_from',
    'valid_until',
    'x_opencti_score',
    'createdBy',
    'objects',
    'sightedBy',
    'x_opencti_detection',
    'based-on',
    'revoked',
    'creator_id',
    'confidence',
    'indicator_types',
    'pattern_type',
    'x_opencti_main_observable_type',
    'containers',
  ];

  const { platformModuleHelpers } = useAuth();
  const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
  const dataColumns: DataColumns = {
    pattern_type: {
      label: 'Type',
      width: '10%',
      isSortable: true,
      render: (stixCoreObject: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data) => {
        if (stixCoreObject.pattern_type) {
          return <ItemPatternType variant="inList" label={stixCoreObject.pattern_type}/>;
        }
        return <></>;
      },
    },
    name: {
      label: 'Name',
      width: '20%',
      isSortable: true,
      render: (stixCoreObject: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data) => getMainRepresentative(stixCoreObject),
    },
    objectLabel: {
      label: 'Labels',
      width: '15%',
      isSortable: false,
      render: (stixCoreObject: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data) => (
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
      render: (stixCoreObject: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data) => nsdt(stixCoreObject.created_at),
    },
    valid_until: {
      label: 'Valid until',
      width: '15%',
      isSortable: true,
      render: (stixCoreObject: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data) => nsdt(stixCoreObject.valid_until),
    },
    objectMarking: {
      label: 'Marking',
      width: '10%',
      isSortable: isRuntimeSort ?? false,
      render: (stixCoreObject: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data) => (
        <ItemMarkings
          variant="inList"
          markingDefinitions={stixCoreObject.objectMarking ?? []}
          limit={1}
        />
      ),
    },
    cases_and_analysis: {
      label: 'Cases & Analyses',
      width: '15%',
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

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, stixCoreObjectTypes);
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
    orderBy: (sortBy && (sortBy in dataColumns) && dataColumns[sortBy].isSortable) ? sortBy : 'name',
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: contextFilters,
  } as unknown as EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery$variables; // Because of FilterMode

  const {
    selectedElements,
    numberOfSelectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>(localStorageKey);

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
        displayImport
        exportContext={{ entity_id: entityId, entity_type: 'Stix-Core-Object' }}
        iconExtension
        filters={contextFilters}
        availableFilterKeys={availableFilterKeys}
        availableRelationshipTypes={relationshipTypes}
        availableEntityTypes={stixCoreObjectTypes}
        numberOfElements={numberOfElements}
        noPadding
        disableCards
        enableEntitiesView
        enableContextualView
        currentView={currentView}
        searchContext={{ elementId: [entityId] }}
      >
        {queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
            <EntityStixCoreRelationshipsIndicatorsContextualViewLines
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              onToggleEntity={onToggleEntity}
              setNumberOfElements={helpers.handleSetNumberOfElements}
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              selectAll={selectAll}
            />
          </React.Suspense>
        ) : (
          <Loader variant={LoaderVariant.inElement}/>
        )}
      </ListLines>
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
    </>
  );
};

const EntityStixCoreRelationshipsIndicatorsContextualView: FunctionComponent<Omit<EntityStixCoreRelationshipsIndicatorsContextualViewProps, 'queryRef'>> = (props) => {
  const queryRef = useQueryLoading<EntityStixCoreRelationshipsIndicatorsContextualViewQuery>(
    contextualViewQuery,
    { id: props.entityId, entityTypes: ['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'] },
  );

  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
      <EntityStixCoreRelationshipsIndicatorsContextualViewComponent {...props} queryRef={queryRef}/>
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement}/>
  );
};

export default EntityStixCoreRelationshipsIndicatorsContextualView;
