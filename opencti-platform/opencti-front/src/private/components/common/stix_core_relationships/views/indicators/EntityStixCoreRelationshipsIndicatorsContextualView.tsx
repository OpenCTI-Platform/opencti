import React, { FunctionComponent } from 'react';
import * as R from 'ramda';
import { graphql, PreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import ItemPatternType from '../../../../../../components/ItemPatternType';
import EntityStixCoreRelationshipsIndicatorsContextualViewLines from './EntityStixCoreRelationshipsIndicatorsContextualViewLines';
import { DataColumns, Filters, PaginationOptions } from '../../../../../../components/list_lines';
import { isEmptyField, isNotEmptyField } from '../../../../../../utils/utils';
import { EntityStixCoreRelationshipsIndicatorsContextualViewQuery } from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewQuery.graphql';
import { PaginationLocalStorage } from '../../../../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../../../../components/i18n';
import usePreloadedFragment from '../../../../../../utils/hooks/usePreloadedFragment';
import {
  EntityStixCoreRelationshipsIndicatorsContextualViewFragment_stixDomainObject$key,
} from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewFragment_stixDomainObject.graphql';
import { cleanFilters, convertFilters } from '../../../../../../utils/ListParameters';
import { EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery$variables } from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery.graphql';
import useEntityToggle from '../../../../../../utils/hooks/useEntityToggle';
import { EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data } from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewLine_node.graphql';
import useAuth from '../../../../../../utils/hooks/useAuth';
import { defaultValue } from '../../../../../../utils/Graph';
import StixCoreObjectLabels from '../../../stix_core_objects/StixCoreObjectLabels';
import ItemMarkings from '../../../../../../components/ItemMarkings';
import ListLines from '../../../../../../components/list_lines/ListLines';
import Loader, { LoaderVariant } from '../../../../../../components/Loader';
import ToolBar from '../../../../data/ToolBar';
import useQueryLoading from '../../../../../../utils/hooks/useQueryLoading';
import { EntityStixCoreRelationshipsContextualViewLine_node$data } from '../__generated__/EntityStixCoreRelationshipsContextualViewLine_node.graphql';
import { resolveLink } from '../../../../../../utils/Entity';
import { Theme } from '../../../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  chip: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: '0',
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
const handleFilterOnContainers = (containers: ({ readonly id: string })[], filters: Filters | undefined) => {
  if (isEmptyField(containers)) {
    return [{ id: '' }]; // Return nothing
  }
  if (isEmptyField(filters)) {
    return containers;
  }

  const selectedContainers = filters?.containers ?? [];
  let filterContainers;
  if (isNotEmptyField(selectedContainers)) {
    const containerIds = containers.map((r) => r.id);
    filterContainers = selectedContainers.filter((r) => isNotEmptyField(r.id) && containerIds.includes(r.id as string));
    if (filterContainers.length === 0) {
      filterContainers = [{ id: '' }]; // Return nothing
    }
  } else {
    filterContainers = containers;
  }
  return filterContainers;
};

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
  const { t, n, nsdt } = useFormatter();

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
    openExports,
  } = viewStorage;

  const availableFilterKeys = [
    'labelledBy',
    'markedBy',
    'created_start_date',
    'created_end_date',
    'valid_from_start_date',
    'valid_until_end_date',
    'x_opencti_score',
    'createdBy',
    'objectContains',
    'sightedBy',
    'x_opencti_detection',
    'basedOn',
    'revoked',
    'creator',
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
          return <ItemPatternType variant="inList" label={stixCoreObject.pattern_type} />;
        }
        return <></>;
      },
    },
    name: {
      label: 'Name',
      width: '20%',
      isSortable: true,
      render: (stixCoreObject: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data) => defaultValue(stixCoreObject),
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
      label: 'Creation date',
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
          markingDefinitionsEdges={stixCoreObject.objectMarking?.edges ?? []}
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

  const cleanedFilters = cleanFilters(filters, availableFilterKeys);

  const finalFilters = {
    ...R.omit(['entity_type', 'containers'], cleanedFilters),
    objectContains: handleFilterOnContainers(containers, cleanedFilters),
  };

  const paginationOptions = {
    search: searchTerm,
    orderBy: (sortBy && (sortBy in dataColumns) && dataColumns[sortBy].isSortable) ? sortBy : 'name',
    orderMode: orderAsc ? 'asc' : 'desc',
    containersIds: containers.map((r) => r.id),
    filters: convertFilters(finalFilters),
  } as unknown as EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery$variables; // Because of FilterMode

  const backgroundTaskFilters = {
    ...finalFilters,
    entity_type: [{ id: 'Indicator', value: 'Indicator' }],
  };

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
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleChangeView={helpers.handleChangeView}
        handleToggleSelectAll={handleToggleSelectAll}
        paginationOptions={paginationOptions}
        selectAll={selectAll}
        keyword={searchTerm}
        displayImport
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportEntityType={'Stix-Core-Object'}
        iconExtension
        filters={cleanedFilters}
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
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
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
          <Loader variant={LoaderVariant.inElement} />
        )}
      </ListLines>
      <ToolBar
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        numberOfSelectedElements={numberOfSelectedElements}
        selectAll={selectAll}
        filters={backgroundTaskFilters}
        search={searchTerm}
        handleClearSelectedElements={handleClearSelectedElements}
        variant="medium"
        warning={true}
        warningMessage={t(
          'Be careful, you are about to delete the selected entities.',
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
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityStixCoreRelationshipsIndicatorsContextualViewComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityStixCoreRelationshipsIndicatorsContextualView;
