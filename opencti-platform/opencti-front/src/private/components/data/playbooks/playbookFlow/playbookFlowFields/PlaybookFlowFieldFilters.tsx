import { Box } from '@mui/material';
import FilterIconButton from '../../../../../../components/FilterIconButton';
import Filters from '../../../../common/lists/Filters';
import useFiltersState from '../../../../../../utils/filters/useFiltersState';
import { stixFilters, useAvailableFilterKeysForEntityTypes } from '../../../../../../utils/filters/filtersUtils';

interface PlaybookFlowFieldFiltersProps {
  componentId: string | null
  filtersState: ReturnType<typeof useFiltersState>
}

const PlaybookFlowFieldFilters = ({
  componentId,
  filtersState,
}: PlaybookFlowFieldFiltersProps) => {
  const [filters, helpers] = filtersState;
  const availableQueryFilterKeys = useAvailableFilterKeysForEntityTypes(
    ['Stix-Core-Object', 'stix-core-relationship'],
  );

  let availableFilterKeys = stixFilters;
  switch (componentId) {
    case 'PLAYBOOK_INTERNAL_DATA_CRON':
      availableFilterKeys = availableQueryFilterKeys;
      break;
    case 'PLAYBOOK_DATA_STREAM_PIR':
      availableFilterKeys = [...stixFilters, 'pir_score'];
      break;
    default:
      break;
  }

  const entityTypes = componentId === 'PLAYBOOK_INTERNAL_DATA_CRON'
    ? ['Stix-Core-Object', 'stix-core-relationship']
    : ['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering'];

  return (
    <div>
      <Box sx={{ display: 'flex', gap: 1, marginTop: 4 }}>
        <Filters
          helpers={helpers}
          availableFilterKeys={availableFilterKeys}
          searchContext={{ entityTypes }}
        />
      </Box>
      <FilterIconButton
        filters={filters}
        helpers={helpers}
        entityTypes={entityTypes}
        searchContext={{ entityTypes }}
        styleNumber={2}
        redirection
      />
    </div>
  );
};

export default PlaybookFlowFieldFilters;
