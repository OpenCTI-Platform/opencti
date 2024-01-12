import Filters from '@components/common/lists/Filters';
import React, { FunctionComponent, useEffect } from 'react';
import { Box } from '@mui/material';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { FilterGroup, isFilterGroupNotEmpty } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';

const entitiesFilters = [
  'entity_type',
  'objectMarking',
  'objectLabel',
  'createdBy',
  'creator_id',
  'workflow_id',
  'objectAssignee',
  'objectParticipant',
  'objects',
  'x_opencti_score',
  'x_opencti_detection',
  'revoked',
  'confidence',
  'pattern_type',
  'killChainPhases',
  'malware_types',
  'report_types',
  'regardingOf',
];

const relationshipsFilters = [
  'fromId',
  'toId',
  'fromTypes',
  'toTypes',
  'relationship_type',
  'objectMarking',
  'objectLabel',
  'createdBy',
  'confidence',
  'killChainPhases',
  'creator_id',
];

const auditsFilters = [
  'entity_type',
  'event_type',
  'event_scope',
  'members_group',
  'members_organization',
  'members_user',
  'contextEntityId',
  'contextEntityType',
  'contextCreatedBy',
  'contextObjectMarking',
  'contextObjectLabel',
  'contextCreator',
];

interface DataSelection {
  label: string;
  attribute: string;
  date_attribute: string;
  perspective: string;
  filters: FilterGroup,
  dynamicFrom: FilterGroup,
  dynamicTo: FilterGroup,
}

interface WidgetFiltersProps {
  perspective: string;
  type: string;
  dataSelection: DataSelection;
  setDataSelection: (data: DataSelection) => void;
}

const WidgetFilters: FunctionComponent<WidgetFiltersProps> = ({ perspective, type, dataSelection, setDataSelection }) => {
  const { t } = useFormatter();
  const [filters, helpers] = useFiltersState(dataSelection.filters);
  const [filtersDynamicFrom, helpersDynamicFrom] = useFiltersState(dataSelection.dynamicFrom);
  const [filtersDynamicTo, helpersDynamicTo] = useFiltersState(dataSelection.dynamicTo);

  useEffect(() => {
    setDataSelection({
      ...dataSelection,
      filters,
      dynamicTo: filtersDynamicTo,
      dynamicFrom: filtersDynamicFrom,
    });
  }, [filters, filtersDynamicFrom, filtersDynamicTo]);

  let availableFilterKeys = entitiesFilters;
  let availableEntityTypes = [
    'Stix-Domain-Object',
    'Stix-Cyber-Observable',
  ];
  if (perspective === 'relationships') {
    availableFilterKeys = relationshipsFilters;
    availableEntityTypes = [
      'Stix-Domain-Object',
      'Stix-Cyber-Observable',
    ];
  } else if (perspective === 'audits') {
    availableFilterKeys = auditsFilters;
    availableEntityTypes = ['History', 'Activity'];
  }
  return <><Box sx={{ display: 'flex', justifyContent: 'space-between', paddingTop: 2 }}>
    <Box sx={{ display: 'flex', gap: 1 }}>
      <Filters
        availableFilterKeys={type === 'bookmark' ? ['entity_type'] : availableFilterKeys}
        availableEntityTypes={availableEntityTypes}
        helpers={helpers}
      />
    </Box>
    { perspective === 'relationships' && (
    <>
      <Box sx={{ display: 'flex', gap: 1 }}>
        <Filters
          availableFilterKeys={entitiesFilters}
          availableEntityTypes={[
            'Stix-Domain-Object',
            'Stix-Cyber-Observable',
          ]}
          helpers={helpersDynamicFrom}
          type="from"
        />
      </Box>
      <Box sx={{ display: 'flex', gap: 1 }}>
        <Filters
          availableFilterKeys={entitiesFilters}
          availableEntityTypes={[
            'Stix-Domain-Object',
            'Stix-Cyber-Observable',
          ]}
          helpers={helpersDynamicTo}

          type="to"
        />
      </Box>
    </>)}
  </Box>
    <Box sx={{ paddingTop: 1 }}>
      <div style={{ marginTop: 8, color: 'orange' }}>{t('Pre-query to get data to be used as source entity of the relationship (limited to 5000)')}</div>
      { isFilterGroupNotEmpty(filtersDynamicFrom) ? (
        <FilterIconButton
          filters={filtersDynamicFrom}
          helpers={helpersDynamicFrom}
          chipColor={'warning'}
        />
      ) : '-' }
      <div style={{ marginTop: 8, color: '#03A847' }}>{t('Pre-query to get data to be used as target entity of the relationship (limited to 5000)')}</div>
      { isFilterGroupNotEmpty(filtersDynamicTo) ? (
        <FilterIconButton
          filters={filtersDynamicTo}
          helpers={helpersDynamicTo}
          chipColor={'success'}
        />
      ) : '-' }
      <div style={{ marginTop: 8 }}>{t('Result: the relationships with source respecting the source pre-query, target respecting the target pre-query, and matching:')}</div>
      { isFilterGroupNotEmpty(filters) && (
        <FilterIconButton
          filters={filters}
          helpers={helpers}
        />
      ) }
    </Box>
  </>;
};

export default WidgetFilters;
