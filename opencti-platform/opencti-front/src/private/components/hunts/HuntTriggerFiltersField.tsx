import React from 'react';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import FilterIconButton from '../../../components/FilterIconButton';
import Filters from '../common/lists/Filters';
import useFiltersState from '../../../utils/filters/useFiltersState';
import { stixFilters } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { HUNT_DOCS } from './hunt-utils';
import { HuntHelp } from './HuntLearnMore';

const ENTITY_TYPES = ['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering'];

interface HuntTriggerFiltersFieldProps {
  filtersState: ReturnType<typeof useFiltersState>;
}

/**
 * Standing hunts re-run when a knowledge change matches these filters. They are evaluated on the
 * stream, so only the stream filter keys are offered (the platform rejects the others).
 */
const HuntTriggerFiltersField = ({ filtersState }: HuntTriggerFiltersFieldProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [filters, helpers] = filtersState;
  const searchContext = { entityTypes: ENTITY_TYPES };

  return (
    <div data-testid="hunt-trigger-filters" style={{ marginTop: theme.spacing(2) }}>
      <Text variant="content-compact" style={{ color: theme.palette.text.secondary, marginBottom: theme.spacing(0.5) }}>
        {t_i18n('Trigger filters')}
      </Text>
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginBottom: theme.spacing(1) }}>
        <Filters
          helpers={helpers}
          availableFilterKeys={stixFilters}
          searchContext={searchContext}
        />
      </div>
      <FilterIconButton
        filters={filters}
        helpers={helpers}
        entityTypes={ENTITY_TYPES}
        searchContext={searchContext}
        redirection
      />
      <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>
        <HuntHelp
          text={t_i18n('The hunt runs again when a created or updated entity matches these filters, for example a new indicator labeled ransomware. Without filters, it runs when new knowledge references its targets, techniques or sources.')}
          href={HUNT_DOCS.standing}
        />
      </Text>
    </div>
  );
};

export default HuntTriggerFiltersField;
