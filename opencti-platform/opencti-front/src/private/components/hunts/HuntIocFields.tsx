import React, { useMemo } from 'react';
import { Field, useFormikContext } from 'formik';
import { useTheme } from '@mui/styles';
import { Chip, Text } from '@filigran/design-system';
import TextareaField from '../../../components/TextareaField';
import FilterIconButton from '../../../components/FilterIconButton';
import Filters from '../common/lists/Filters';
import HuntEntitiesField from './HuntEntitiesField';
import useFiltersState from '../../../utils/filters/useFiltersState';
import { useAvailableFilterKeysForEntityTypes } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import { iocTypeLabel, parseIocText } from './hunt-ioc-utils';
import { HUNT_DOCS, HUNT_IOC_ELEMENT_TYPES, HUNT_IOC_ENTITY_TYPES } from './hunt-utils';
import { HuntHelp } from './HuntLearnMore';

const IOC_FILTER_ENTITY_TYPES = ['Indicator', 'Stix-Cyber-Observable'];
const INVALID_SHOWN_MAX = 5;

/** What the pasted text holds: the values by type, and what is not a value an indicator hunt looks up. */
export const HuntIocTextSummary = ({ text }: { text: string }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const parsed = useMemo(() => parseIocText(text), [text]);
  if (text.trim().length === 0) {
    return null;
  }
  const byType = new Map<string, number>();
  parsed.values.forEach((value) => byType.set(value.observable_type, (byType.get(value.observable_type) ?? 0) + 1));
  return (
    <div role="status" aria-live="polite" data-testid="hunt-ioc-text-summary" style={{ marginTop: theme.spacing(1), display: 'flex', flexDirection: 'column', gap: theme.spacing(0.5) }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(0.5), flexWrap: 'wrap' }}>
        <Text variant="content-compact-bold">
          {t_i18n('{count} values recognized', { values: { count: n(parsed.values.length) } })}
        </Text>
        {Array.from(byType.entries()).map(([type, count]) => (
          <Chip key={type} label={`${iocTypeLabel(type, t_i18n)}: ${n(count)}`} />
        ))}
        {parsed.duplicates > 0 && (
          <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>
            {t_i18n('{count} duplicates removed', { values: { count: n(parsed.duplicates) } })}
          </Text>
        )}
      </div>
      {parsed.invalid.length > 0 && (
        <Text variant="content-caption" style={{ color: theme.palette.error.main }} data-testid="hunt-ioc-text-invalid">
          {t_i18n('Not recognized, left out: {values}', {
            values: {
              values: `${parsed.invalid.slice(0, INVALID_SHOWN_MAX).join(', ')}${parsed.invalid.length > INVALID_SHOWN_MAX ? ` +${parsed.invalid.length - INVALID_SHOWN_MAX}` : ''}`,
            },
          })}
        </Text>
      )}
    </div>
  );
};

interface HuntIocFieldsProps {
  filtersState: ReturnType<typeof useFiltersState>;
  disabled?: boolean;
  /** The filter builder opens MUI popovers, which a modal design-system dialog cannot host: dialogs leave it out */
  withFilters?: boolean;
}

/**
 * What an indicator hunt looks for, four ways that add up: indicators and observables picked from a list, the
 * indicators and observables of entities, values pasted as text, and the ones matching a filter.
 */
const HuntIocFields = ({ filtersState, disabled = false, withFilters = true }: HuntIocFieldsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { values } = useFormikContext<{ ioc_values_text: string }>();
  const [filters, helpers] = filtersState;
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(IOC_FILTER_ENTITY_TYPES);
  const searchContext = { entityTypes: IOC_FILTER_ENTITY_TYPES };
  return (
    <div data-testid="hunt-ioc-fields">
      <HuntEntitiesField
        name="iocElements"
        label={t_i18n('Indicators and observables')}
        types={HUNT_IOC_ELEMENT_TYPES}
        disabled={disabled}
        helpertext={t_i18n('Pick the indicators and observables to look for, for example the IP addresses of a campaign')}
        style={fieldSpacingContainerStyle}
      />
      <HuntEntitiesField
        name="iocEntities"
        label={t_i18n('Take them from')}
        types={HUNT_IOC_ENTITY_TYPES}
        disabled={disabled}
        helpertext={t_i18n('Every indicator and observable of a report, a grouping, an incident response, a threat or an incident, read again at every run')}
        style={fieldSpacingContainerStyle}
      />
      <div style={fieldSpacingContainerStyle}>
        <Field
          component={TextareaField}
          name="ioc_values_text"
          label={t_i18n('Paste values')}
          rows={5}
          disabled={disabled}
          helperText={t_i18n('IP addresses, domains, URLs, file hashes or email addresses, one per line or separated by commas. Defanged values (hxxp, [.]) are restored.')}
          data-testid="hunt-ioc-text"
        />
        <HuntIocTextSummary text={values.ioc_values_text ?? ''} />
      </div>
      {withFilters ? (
        <div style={fieldSpacingContainerStyle} data-testid="hunt-ioc-filters">
          <Text variant="content-compact" style={{ color: theme.palette.text.secondary, marginBottom: theme.spacing(0.5) }}>
            {t_i18n('Or the ones matching a filter')}
          </Text>
          {!disabled && (
            <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginBottom: theme.spacing(1) }}>
              <Filters helpers={helpers} availableFilterKeys={availableFilterKeys} searchContext={searchContext} />
            </div>
          )}
          <FilterIconButton filters={filters} helpers={helpers} entityTypes={IOC_FILTER_ENTITY_TYPES} searchContext={searchContext} redirection />
          <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>
            <HuntHelp
              text={t_i18n('For example the indicators labelled apt28 that are still valid. Without a filter, only the values above are looked for.')}
              href={HUNT_DOCS.indicatorSources}
            />
          </Text>
        </div>
      ) : (
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(2), color: theme.palette.text.secondary }} data-testid="hunt-ioc-filters-elsewhere">
          {t_i18n('To look for the indicators matching a filter, add the filter from the Logic tab of the hunt once it is created.')}
        </Text>
      )}
    </div>
  );
};

export default HuntIocFields;
