import React, { FunctionComponent, useState } from 'react';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { AccountTreeOutlined } from '@mui/icons-material';
import FilterBuilderDialog from './FilterBuilderDialog';
import { useFormatter } from '../i18n';
import { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import { FilterSearchContext } from '../../utils/filters/filtersUtils';

interface FilterBuilderButtonProps {
  filters: FilterGroup;
  onSubmit: (filters: FilterGroup) => void;
  availableFilterKeys: string[];
  entityTypes: string[];
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  searchContext?: FilterSearchContext;
  disabled?: boolean;
}

const FilterBuilderButton: FunctionComponent<FilterBuilderButtonProps> = ({
  filters,
  onSubmit,
  availableFilterKeys,
  entityTypes,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
  disabled = false,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const hasNestedGroups = (filters?.filterGroups?.length ?? 0) > 0;

  return (
    <>
      <Tooltip title={t_i18n('Advanced filter builder')}>
        <IconButton
          color={hasNestedGroups ? 'primary' : 'default'}
          size="small"
          disabled={disabled}
          onClick={() => setOpen(true)}
        >
          <AccountTreeOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <FilterBuilderDialog
        open={open}
        onClose={() => setOpen(false)}
        initialFilters={filters}
        onSubmit={onSubmit}
        availableFilterKeys={availableFilterKeys}
        entityTypes={entityTypes}
        availableEntityTypes={availableEntityTypes}
        availableRelationshipTypes={availableRelationshipTypes}
        availableRelationFilterTypes={availableRelationFilterTypes}
        searchContext={searchContext}
      />
    </>
  );
};

export default FilterBuilderButton;
