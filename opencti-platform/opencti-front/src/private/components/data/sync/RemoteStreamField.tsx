import React, { CSSProperties, FunctionComponent, useCallback, useMemo } from 'react';
import { Field, getIn, useFormikContext } from 'formik';
import ComboboxField from '../../../../components/ComboboxField';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmptyShallow } from '../../../../utils/filters/filtersUtils';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { countRemoteStreamFilters, filterRemoteStreams, RemoteStreamOption, shouldGroupRemoteStreams, sortRemoteStreams, splitStreamName } from './remoteStreamOptions';

const oneLine: CSSProperties = { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' };
const secondaryText: CSSProperties = { fontSize: 12, color: 'var(--text-default-secondary)' };

interface RemoteStreamFieldProps {
  /** Formik field holding the stream id, a string: the value and its validation stay those of the form. */
  name: string;
  label: string;
  streams: RemoteStreamOption[];
  disabled?: boolean;
  required?: boolean;
}

/**
 * Picker of the live stream a synchronizer consumes on a remote OpenCTI. A remote
 * platform can expose dozens of streams, so it is a full-width searchable
 * combobox (name and description, case and accent insensitive) with compact
 * two-line rows, and the picked stream's description and filters are shown
 * under the field instead of behind a hover.
 */
const RemoteStreamField: FunctionComponent<RemoteStreamFieldProps> = ({
  name,
  label,
  streams,
  disabled = false,
  required = false,
}) => {
  const { t_i18n } = useFormatter();
  const { values, setFieldValue } = useFormikContext<Record<string, unknown>>();
  const selectedId = getIn(values, name) as string | null | undefined;

  const options = useMemo(() => sortRemoteStreams(streams), [streams]);
  const grouped = useMemo(() => shouldGroupRemoteStreams(options), [options]);
  const byId = useMemo(() => new Map(options.map((stream) => [stream.value, stream])), [options]);
  const selected = selectedId ? byId.get(selectedId) : undefined;
  const selectedFilters = useMemo(
    () => (selected?.filters ? deserializeFilterGroupForFrontend(selected.filters) : null),
    [selected],
  );

  // The form holds the id string while the options are objects: both shapes reach these callbacks.
  const getOptionLabel = useCallback(
    (option: RemoteStreamOption | string) => (typeof option === 'string' ? (byId.get(option)?.name ?? option) : option.name),
    [byId],
  );
  const handleChange = useCallback((fieldName: string, next: RemoteStreamOption | string | RemoteStreamOption[] | null) => {
    const picked = Array.isArray(next) ? next[0] : next;
    setFieldValue(fieldName, typeof picked === 'string' ? picked : (picked?.value ?? ''));
  }, [setFieldValue]);

  const renderOption = (option: RemoteStreamOption | string) => {
    if (typeof option === 'string') return option;
    const filterCount = countRemoteStreamFilters(option.filters);
    return (
      <span style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%', minWidth: 0 }}>
        <span style={{ display: 'flex', flexDirection: 'column', flex: 1, minWidth: 0 }}>
          <span style={oneLine}>{grouped ? splitStreamName(option.name).title : option.name}</span>
          <span style={{ ...oneLine, ...secondaryText }}>
            {option.description || t_i18n('No description')}
          </span>
        </span>
        <span style={{ ...secondaryText, flexShrink: 0, whiteSpace: 'nowrap' }}>
          {filterCount > 0
            ? t_i18n('{count, plural, one {# filter} other {# filters}}', { values: { count: filterCount } })
            : t_i18n('No filter')}
        </span>
      </span>
    );
  };

  return (
    <div style={fieldSpacingContainerStyle}>
      <Field
        component={ComboboxField}
        name={name}
        id={name}
        label={label}
        required={required}
        disabled={disabled}
        multiple={false}
        clearable={false}
        options={options}
        placeholder={t_i18n('Search a stream')}
        helperText={disabled ? undefined : t_i18n(
          '{count, plural, one {# stream available} other {# streams available}}',
          { values: { count: options.length } },
        )}
        noOptionsText={t_i18n('No stream matches')}
        getOptionLabel={getOptionLabel}
        filterOptions={(list: RemoteStreamOption[], input: string) => filterRemoteStreams(list, input)}
        groupBy={grouped ? (option: RemoteStreamOption) => splitStreamName(option.name).group ?? '' : undefined}
        renderOption={renderOption}
        isOptionTwoLine={() => true}
        // About seven two-line rows, then the list scrolls.
        listClassName="max-h-85.5"
        onInternalChange={handleChange}
      />
      {selected && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 8 }}>
          {selected.description && <span style={secondaryText}>{selected.description}</span>}
          {selectedFilters && isFilterGroupNotEmptyShallow(selectedFilters)
            ? <FilterIconButton filters={selectedFilters} variant="small" />
            : <span style={secondaryText}>{t_i18n('No filter')}</span>}
        </div>
      )}
    </div>
  );
};

export default RemoteStreamField;
