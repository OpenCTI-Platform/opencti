import { AccountBalanceOutlined, CenterFocusStrongOutlined, DateRangeOutlined, FilterAltOffOutlined, FilterListOutlined } from '@mui/icons-material';
import Badge from '@mui/material/Badge';
import React, { useState } from 'react';
import GraphToolbarOptionsList from './GraphToolbarOptionsList';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../../components/i18n';
import { useGraphContext } from '../GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';

const GraphToolbarFilterTools = () => {
  const { t_i18n } = useFormatter();
  const [filterByTypeAnchor, setFilterByTypeAnchor] = useState<Element>();
  const [filterByMarkingAnchor, setFilterByMarkingAnchor] = useState<Element>();
  const [filterByCreatorAnchor, setFilterByCreatorAnchor] = useState<Element>();

  const {
    stixCoreObjectTypes,
    markingDefinitions,
    creators,
    graphState: {
      showTimeRange,
      disabledEntityTypes,
      disabledMarkings,
      disabledCreators,
    },
  } = useGraphContext();

  const {
    toggleTimeRange,
    toggleEntityType,
    toggleCreator,
    toggleMarkingDefinition,
    resetFilters,
  } = useGraphInteractions();

  return (
    <>
      <GraphToolbarItem
        Icon={<DateRangeOutlined />}
        color={showTimeRange ? 'secondary' : 'primary'}
        onClick={toggleTimeRange}
        title={t_i18n('Display time range selector')}
      />

      <GraphToolbarItem
        Icon={(
          <Badge badgeContent={disabledEntityTypes.length} color="secondary">
            <FilterListOutlined />
          </Badge>
        )}
        disabled={stixCoreObjectTypes.length === 0}
        color="primary"
        onClick={(e) => setFilterByTypeAnchor(e.currentTarget)}
        title={t_i18n('Filter entity types')}
      />
      <GraphToolbarOptionsList
        isMultiple
        anchorEl={filterByTypeAnchor}
        onClose={() => setFilterByTypeAnchor(undefined)}
        options={stixCoreObjectTypes}
        getOptionKey={(type) => type}
        getOptionText={(type) => t_i18n(`entity_${type}`)}
        isOptionSelected={(type) => !disabledEntityTypes.includes(type)}
        onSelect={toggleEntityType}
      />

      <GraphToolbarItem
        Icon={(
          <Badge badgeContent={disabledMarkings.length} color="secondary">
            <CenterFocusStrongOutlined />
          </Badge>
        )}
        disabled={markingDefinitions.length === 0}
        color="primary"
        onClick={(e) => setFilterByMarkingAnchor(e.currentTarget)}
        title={t_i18n('Filter marking definitions')}
      />
      <GraphToolbarOptionsList
        isMultiple
        anchorEl={filterByMarkingAnchor}
        onClose={() => setFilterByMarkingAnchor(undefined)}
        options={markingDefinitions}
        getOptionKey={(marking) => marking.id}
        getOptionText={(marking) => marking.definition}
        isOptionSelected={(marking) => !disabledMarkings.includes(marking.id)}
        onSelect={(marking) => toggleMarkingDefinition(marking.id)}
      />

      <GraphToolbarItem
        Icon={(
          <Badge badgeContent={disabledCreators.length} color="secondary">
            <AccountBalanceOutlined />
          </Badge>
        )}
        disabled={creators.length === 0}
        color="primary"
        onClick={(e) => setFilterByCreatorAnchor(e.currentTarget)}
        title={t_i18n('Filter authors (created by)')}
      />
      <GraphToolbarOptionsList
        isMultiple
        anchorEl={filterByCreatorAnchor}
        onClose={() => setFilterByCreatorAnchor(undefined)}
        options={creators}
        getOptionKey={(creator) => creator.id}
        getOptionText={(creator) => creator.name}
        isOptionSelected={(creator) => !disabledCreators.includes(creator.id)}
        onSelect={(creator) => toggleCreator(creator.id)}
      />

      <GraphToolbarItem
        Icon={<FilterAltOffOutlined />}
        color="primary"
        onClick={resetFilters}
        title={t_i18n('Clear all filters')}
      />
    </>
  );
};

export default GraphToolbarFilterTools;
