import { Box } from '@mui/material';
import Filters from '@components/common/lists/Filters';
import FilterIconButton from '../../../../../components/FilterIconButton';
import useFiltersState from '../../../../../utils/filters/useFiltersState';
import type { FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';
import { emptyFilterGroup, stixFilters, useAvailableFilterKeysForEntityTypes } from '../../../../../utils/filters/filtersUtils';
import { useEffect } from 'react';
import { FieldProps } from 'formik';

interface WorkflowCondition {
  filters?: FilterGroup;
  filterGroup?: string;
  mode?: string;
}

interface WorkflowConditionFiltersProps extends FieldProps<WorkflowCondition> {
  entityType?: string;
}

// Keys evaluated against the user triggering the transition (and the entity name)
export const WORKFLOW_CONTEXT_FILTER_KEYS = [
  'name',
  'workflow_user',
  'workflow_group',
  'workflow_organization',
];

// Entity attribute keys are evaluated by the backend stix filtering engine, so only stix compatible keys are offered.
// entity_type is dropped: it always equals the workflow entity type.
export const getWorkflowConditionFilterKeys = (entityFilterKeys: string[]) => {
  const entityKeys = entityFilterKeys.filter((key) => key !== 'entity_type'
    && stixFilters.includes(key)
    && !WORKFLOW_CONTEXT_FILTER_KEYS.includes(key));
  return [...WORKFLOW_CONTEXT_FILTER_KEYS, ...entityKeys];
};

const WorkflowConditionFilters = ({
  form,
  field,
  entityType,
}: WorkflowConditionFiltersProps) => {
  const { setFieldValue } = form;
  const { name, value } = field;

  const [filters, helpers] = useFiltersState(value?.filters || emptyFilterGroup);
  const entityFilterKeys = useAvailableFilterKeysForEntityTypes(entityType ? [entityType] : []);
  const availableFilterKeys = getWorkflowConditionFilterKeys(entityFilterKeys);
  const contextEntityTypes = ['User', 'Group', 'Organization', 'DraftWorkspace'];
  const availableEntityTypes = entityType && !contextEntityTypes.includes(entityType)
    ? [...contextEntityTypes, entityType]
    : contextEntityTypes;
  const searchContext = { entityTypes: availableEntityTypes };

  useEffect(() => {
    setFieldValue(name, {
      filters,
      filterGroup: value?.filterGroup,
      mode: value?.mode,
    });
  }, [filters]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center' }}>
        <Filters
          availableFilterKeys={availableFilterKeys}
          availableEntityTypes={availableEntityTypes}
          helpers={helpers}
          searchContext={searchContext}
        />
      </Box>
      <FilterIconButton
        filters={filters}
        helpers={helpers}
        availableFilterKeys={availableFilterKeys}
        searchContext={searchContext}
        availableEntityTypes={availableEntityTypes}
        entityTypes={searchContext.entityTypes}
      />
    </Box>
  );
};

export default WorkflowConditionFilters;
