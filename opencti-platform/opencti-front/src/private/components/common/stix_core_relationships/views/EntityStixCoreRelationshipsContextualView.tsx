import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLines from '../../../../../components/list_lines/ListLines';
import { PaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import useAuth from '../../../../../utils/hooks/useAuth';
import useEntityToggle from '../../../../../utils/hooks/useEntityToggle';
import EntityStixCoreRelationshipsContextualViewLines from './EntityStixCoreRelationshipsContextualViewLines';
import { hexToRGB, itemColor } from '../../../../../utils/Colors';
import { useFormatter } from '../../../../../components/i18n';
import { defaultValue } from '../../../../../utils/Graph';
import StixCoreObjectLabels from '../../stix_core_objects/StixCoreObjectLabels';
import ItemMarkings from '../../../../../components/ItemMarkings';
import { Filters, PaginationOptions } from '../../../../../components/list_lines';
import { cleanFilters, convertFilters } from '../../../../../utils/ListParameters';
import ToolBar from '../../../data/ToolBar';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import usePreloadedFragment from '../../../../../utils/hooks/usePreloadedFragment';
import { isEmptyField, isNotEmptyField } from '../../../../../utils/utils';
import { EntityStixCoreRelationshipsContextualViewQuery } from './__generated__/EntityStixCoreRelationshipsContextualViewQuery.graphql';
import { EntityStixCoreRelationshipsContextualViewFragment_stixDomainObject$key } from './__generated__/EntityStixCoreRelationshipsContextualViewFragment_stixDomainObject.graphql';
import { EntityStixCoreRelationshipsContextualViewLinesQuery$variables } from './__generated__/EntityStixCoreRelationshipsContextualViewLinesQuery.graphql';
import { EntityStixCoreRelationshipsContextualViewLine_node$data } from './__generated__/EntityStixCoreRelationshipsContextualViewLine_node.graphql';

const useStyles = makeStyles(() => ({
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
}));

const contextualViewFragment = graphql`
  fragment EntityStixCoreRelationshipsContextualViewFragment_stixDomainObject on StixDomainObject {
    reports {
      edges {
        node {
          id
        }
      }
    }
  }
`;

const contextualViewQuery = graphql`
  query EntityStixCoreRelationshipsContextualViewQuery($id: String!) {
    stixDomainObject(id: $id) {
      ...EntityStixCoreRelationshipsContextualViewFragment_stixDomainObject
    }
  }
`;
const handleFilterOnReports = (reports: ({ readonly id: string })[], filters: Filters | undefined) => {
  if (isEmptyField(reports)) {
    return [{ id: '' }]; // Return nothing
  }

  const selectedReports = filters?.reports ?? [];
  let filterReport;
  if (isNotEmptyField(selectedReports)) {
    const reportIds = reports.map((r) => r.id);
    filterReport = selectedReports.filter((r) => isNotEmptyField(r.id) && reportIds.includes(r.id as string));
    if (filterReport.length === 0) {
      filterReport = [{ id: '' }]; // Return nothing
    }
  } else {
    filterReport = reports;
  }
  return filterReport;
};

interface EntityStixCoreRelationshipsContextualViewProps {
  queryRef: PreloadedQuery<EntityStixCoreRelationshipsContextualViewQuery>
  entityId: string
  entityLink: string
  localStorage: PaginationLocalStorage<PaginationOptions>
  relationshipTypes: string[]
  stixCoreObjectTypes: string[]
  currentView: string
}
const EntityStixCoreRelationshipsContextualViewComponent: FunctionComponent<Omit<EntityStixCoreRelationshipsContextualViewProps, 'entityId'>> = ({
  queryRef,
  entityLink,
  localStorage,
  relationshipTypes = [],
  stixCoreObjectTypes = [],
  currentView,
}) => {
  const classes = useStyles();
  const { t, nsdt } = useFormatter();

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
    'entity_type',
    'markedBy',
    'confidence',
    'labelledBy',
    'createdBy',
    'creator',
    'created_start_date',
    'created_end_date',
    'reports',
  ];

  const selectedTypes = filters?.entity_type?.map((o) => o.id) as string[] ?? stixCoreObjectTypes;
  const reports = stixDomainObject.reports?.edges?.map((e) => e?.node)
    .filter((r) => isNotEmptyField(r)) as { id: string }[] ?? [];

  const cleanedFilters = cleanFilters(filters, availableFilterKeys);

  const finalFilters = {
    ...R.omit(['entity_type', 'reports'], cleanedFilters),
    objectContains: handleFilterOnReports(reports, cleanedFilters),
  };

  const paginationOptions = {
    search: searchTerm,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
    types: selectedTypes,
    reportIds: reports.map((r) => r.id),
    filters: convertFilters(finalFilters),
  } as unknown as EntityStixCoreRelationshipsContextualViewLinesQuery$variables; // Because of FilterMode

  const backgroundTaskFilters = {
    ...finalFilters,
    entity_type:
    selectedTypes.length > 0
      ? selectedTypes.map((n) => ({ id: n, value: n }))
      : [{ id: 'Stix-Core-Object', value: 'Stix-Core-Object' }],
  };

  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>(localStorageKey);

  const { platformModuleHelpers } = useAuth();
  const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable();
  const dataColumns = {
    entity_type: {
      label: 'Type',
      width: '10%',
      isSortable: true,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => (
        <Chip
          classes={{ root: classes.chipInList }}
          style={{
            backgroundColor: hexToRGB(itemColor(stixCoreObject.entity_type), 0.08),
            color: itemColor(stixCoreObject.entity_type),
            border: `1px solid ${itemColor(stixCoreObject.entity_type)}`,
          }}
          label={t(`entity_${stixCoreObject.entity_type}`)}
        />
      ),
    },
    observable_value: {
      label: 'Value',
      width: '20%',
      isSortable: isRuntimeSort ?? false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => defaultValue(stixCoreObject),
    },
    createdBy: {
      label: 'Author',
      width: '10%',
      isSortable: isRuntimeSort ?? false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => R.pathOr('', ['createdBy', 'name'], stixCoreObject),
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
      label: 'Creation date',
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
          markingDefinitionsEdges={stixCoreObject.objectMarking?.edges ?? []}
          limit={1}
        />
      ),
    },
    report: {
      label: 'Report',
      width: '10%',
      isSortable: false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => stixCoreObject.reports?.edges?.map((e) => e?.node).map((n) => n?.name).join(','),
    },
  };

  let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
  if (selectAll) {
    numberOfSelectedElements = (numberOfElements?.original ?? 0) - Object.keys(deSelectedElements || {}).length;
  }

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
        displayImport={true}
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportEntityType={'Stix-Core-Object'}
        iconExtension={true}
        filters={cleanedFilters}
        availableFilterKeys={availableFilterKeys}
        availableRelationshipTypes={relationshipTypes}
        availableEntityTypes={stixCoreObjectTypes}
        numberOfElements={numberOfElements}
        noPadding={true}
        disableCards={true}
        enableEntitiesView={true}
        enableContextualView={true}
        currentView={currentView}
      >
        {queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <EntityStixCoreRelationshipsContextualViewLines
              entityLink={entityLink}
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

const EntityStixCoreRelationshipsContextualView: FunctionComponent<Omit<EntityStixCoreRelationshipsContextualViewProps, 'queryRef'>> = (props) => {
  const queryRef = useQueryLoading<EntityStixCoreRelationshipsContextualViewQuery>(contextualViewQuery, { id: props.entityId });

  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityStixCoreRelationshipsContextualViewComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityStixCoreRelationshipsContextualView;
