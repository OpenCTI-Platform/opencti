import React from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import ListLines from '../../../../../components/list_lines/ListLines';
import { PaginationLocalStorage, UseLocalStorageHelpers } from '../../../../../utils/hooks/useLocalStorage';
import useAuth from '../../../../../utils/hooks/useAuth';
import useEntityToggle from '../../../../../utils/hooks/useEntityToggle';
import EntityStixCoreRelationshipsContextualViewLines from './EntityStixCoreRelationshipsContextualViewLines';
import { Theme } from '../../../../../components/Theme';
import { hexToRGB, itemColor } from '../../../../../utils/Colors';
import { useFormatter } from '../../../../../components/i18n';
import { defaultValue } from '../../../../../utils/Graph';
import StixCoreObjectLabels from '../../stix_core_objects/StixCoreObjectLabels';
import ItemMarkings from '../../../../../components/ItemMarkings';
import { EntityStixCoreRelationshipsContextualViewLine_node$data } from './__generated__/EntityStixCoreRelationshipsContextualViewLine_node.graphql';
import { PaginationOptions } from '../../../../../components/list_lines';
import { EntityStixCoreRelationshipsContextualViewLinesQuery$variables } from './__generated__/EntityStixCoreRelationshipsContextualViewLinesQuery.graphql';

const useStyles = makeStyles<Theme>(() => ({
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
}));

const EntityStixCoreRelationshipsContextualView = ({
  entityId,
  currentView,
  entityLink,
  relationshipTypes,
  stixCoreObjectTypes,
  handleChangeView,
  paginationLocalStorage,
}: {
  entityId: string
  currentView: string
  entityLink: string
  relationshipTypes: string[]
  stixCoreObjectTypes: string[]
  handleChangeView: UseLocalStorageHelpers['handleChangeView']
  paginationLocalStorage: PaginationLocalStorage<PaginationOptions>
}) => {
  const classes = useStyles();
  const { t, nsdt } = useFormatter();

  const { viewStorage, helpers, paginationOptions, localStorageKey } = paginationLocalStorage;

  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
  } = viewStorage;

  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>(localStorageKey);

  const { platformModuleHelpers } = useAuth();
  const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable();
  const dataColumns = {
    entity_type: {
      label: 'Type',
      width: '12%',
      isSortable: true,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => (
        <Chip
          classes={{ root: classes.chipInList }}
          style={{
            backgroundColor: hexToRGB(
              itemColor(stixCoreObject.entity_type),
              0.08,
            ),
            color: itemColor(stixCoreObject.entity_type),
            border: `1px solid ${itemColor(stixCoreObject.entity_type)}`,
          }}
          label={t(`entity_${stixCoreObject.entity_type}`)}
        />
      ),
    },
    observable_value: {
      label: 'Value',
      width: '25%',
      isSortable: isRuntimeSort ?? false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => defaultValue(stixCoreObject),
    },
    createdBy: {
      label: 'Author',
      width: '12%',
      isSortable: isRuntimeSort ?? false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => R.pathOr('', ['createdBy', 'name'], stixCoreObject),
    },
    creator: {
      label: 'Creators',
      width: '12%',
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
      width: '8%',
      isSortable: isRuntimeSort ?? false,
      render: (stixCoreObject: EntityStixCoreRelationshipsContextualViewLine_node$data) => (
        <ItemMarkings
          variant="inList"
          markingDefinitionsEdges={
            stixCoreObject.objectMarking?.edges ?? []
          }
          limit={1}
        />
      ),
    },
  };

  return (
    <div className={classes.container}>
    <ListLines
      sortBy={sortBy}
      orderAsc={orderAsc}
      dataColumns={dataColumns}
      handleSort={helpers.handleSort}
      handleSearch={helpers.handleSearch}
      handleAddFilter={helpers.handleAddFilter}
      handleRemoveFilter={helpers.handleRemoveFilter}
      handleChangeView={handleChangeView}
      handleToggleSelectAll={handleToggleSelectAll}
      paginationOptions={paginationOptions}
      selectAll={selectAll}
      keyword={searchTerm}
      displayImport={true}
      handleToggleExports={helpers.handleToggleExports}
      openExports={openExports}
      exportEntityType={'Stix-Core-Object'}
      iconExtension={true}
      filters={filters}
      availableFilterKeys={[
        'relationship_type',
        'entity_type',
        'markedBy',
        'labelledBy',
        'createdBy',
        'creator',
        'created_start_date',
        'created_end_date',
      ]}

      availableRelationshipTypes={relationshipTypes}
      availableEntityTypes={stixCoreObjectTypes}

      numberOfElements={numberOfElements}
      noPadding={true}
      disableCards={true}
      enableEntitiesView={true}
      enableContextualView={true}
      currentView={currentView}
    >
      <EntityStixCoreRelationshipsContextualViewLines
        entityId={entityId}
        entityLink={entityLink}
        entityTypes={stixCoreObjectTypes}
        containerType={'Report'}
        paginationOptions={paginationOptions as Partial<EntityStixCoreRelationshipsContextualViewLinesQuery$variables>}
        dataColumns={dataColumns}
        onToggleEntity={onToggleEntity}
        setNumberOfElements={helpers.handleSetNumberOfElements}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        selectAll={selectAll}
      />
    </ListLines>
    </div>
  );
};

export default EntityStixCoreRelationshipsContextualView;
