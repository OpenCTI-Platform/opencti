import { Box } from '@mui/material';
import Filters from '@components/common/lists/Filters';
import FilterIconButton from '../../../../../components/FilterIconButton';
import useFiltersState from '../../../../../utils/filters/useFiltersState';
import { FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';
import { emptyFilterGroup } from '../../../../../utils/filters/filtersUtils';
import { useEffect } from 'react';
import { FieldProps } from 'formik';

interface WorkflowCondition {
  filters?: FilterGroup;
  filterGroup?: string;
  mode?: string;
}

const WorkflowConditionFilters = ({
  form,
  field,
}: FieldProps<WorkflowCondition>) => {
  const { setFieldValue } = form;
  const { name, value } = field;

  const [filters, helpers] = useFiltersState(value?.filters || emptyFilterGroup);
  const availableEntityTypes = ['User', 'Group', 'Organization', 'Location', 'Sector', 'DraftWorkspace'];
  const availableFilterKeys = [
    'name',
    'workflow_id',
    'workflow_user',
    'workflow_group',
    'workflow_organization',
  ];
  const searchContext = { entityTypes: availableEntityTypes };

  useEffect(() => {
    setFieldValue(name, {
      filters,
      filterGroup: value?.filterGroup,
      mode: value?.mode,
    });
  }, [filters]);

  return (
    <>
      <Box sx={{ display: 'flex', alignItems: 'center' }}>
        <Filters
          availableFilterKeys={availableFilterKeys}
          availableEntityTypes={availableEntityTypes}
          helpers={helpers}
          searchContext={searchContext}
        />
      </Box>
      <Box>
        <FilterIconButton
          filters={filters}
          helpers={helpers}
          searchContext={searchContext}
          availableEntityTypes={availableEntityTypes}
          entityTypes={searchContext.entityTypes}
        />
      </Box>
    </>
  );
};

export default WorkflowConditionFilters;
