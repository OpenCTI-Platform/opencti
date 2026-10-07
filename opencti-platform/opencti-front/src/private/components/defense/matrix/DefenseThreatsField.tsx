import React, { useEffect, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { Combobox, ComboboxChips, ComboboxClear, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput, ComboboxTrigger } from '@filigran/design-system';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { DEFENSE_THREAT_TYPES, type DefenseThreatOption } from './defenseMatrix-utils';
import { DefenseThreatsFieldSearchQuery$data } from './__generated__/DefenseThreatsFieldSearchQuery.graphql';
import { DefenseThreatsFieldAccessQuery$data } from './__generated__/DefenseThreatsFieldAccessQuery.graphql';

const SEARCH_DEBOUNCE_MS = 300;
const SEARCH_SIZE = 25;

const defenseThreatsFieldAccessQuery = graphql`
  query DefenseThreatsFieldAccessQuery($types: [String], $filters: FilterGroup, $first: Int) {
    stixDomainObjects(types: $types, filters: $filters, first: $first) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

const defenseThreatsFieldSearchQuery = graphql`
  query DefenseThreatsFieldSearchQuery($types: [String], $search: String, $first: Int) {
    stixDomainObjects(types: $types, search: $search, first: $first, orderBy: _score, orderMode: desc) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

interface DefenseThreatsFieldProps {
  value: DefenseThreatOption[];
  onChange: (threats: DefenseThreatOption[]) => void;
}

const DefenseThreatsField = ({ value, onChange }: DefenseThreatsFieldProps) => {
  const { t_i18n } = useFormatter();
  const [options, setOptions] = useState<DefenseThreatOption[]>([]);
  const [loading, setLoading] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const requestId = useRef(0);
  // A threat of the stored scope is shown only once the reader is known to access it: the threats picked from the search
  // are, the others are confirmed by one query, which also drops the threats no longer accessible and refreshes the names
  const [confirmedIds, setConfirmedIds] = useState<ReadonlySet<string>>(() => new Set());
  const latest = useRef({ value, onChange });
  latest.current = { value, onChange };
  const unconfirmedKey = value.filter((threat) => !confirmedIds.has(threat.value)).map((threat) => threat.value).join(',');

  useEffect(() => {
    if (!unconfirmedKey) return undefined;
    const unconfirmedIds = unconfirmedKey.split(',');
    let cancelled = false;
    fetchQuery(defenseThreatsFieldAccessQuery, {
      types: DEFENSE_THREAT_TYPES,
      filters: { mode: 'and' as const, filters: [{ key: ['ids'], values: unconfirmedIds }], filterGroups: [] },
      first: unconfirmedIds.length,
    })
      .toPromise()
      .then((data) => {
        if (cancelled) return;
        const edges = (data as DefenseThreatsFieldAccessQuery$data | undefined)?.stixDomainObjects?.edges ?? [];
        const accessible = new Map(edges.map(({ node }) => [node.id, { value: node.id, label: node.representative.main, type: node.entity_type }]));
        setConfirmedIds((current) => new Set([...current, ...accessible.keys()]));
        const current = latest.current.value;
        const next = current
          .filter((threat) => !unconfirmedIds.includes(threat.value) || accessible.has(threat.value))
          .map((threat) => accessible.get(threat.value) ?? threat);
        if (JSON.stringify(next) !== JSON.stringify(current)) latest.current.onChange(next);
      })
      .catch(() => {
        // The threats stay hidden: they are asked again the next time the field is shown
      });
    return () => {
      cancelled = true;
    };
  }, [unconfirmedKey]);

  const search = (input: string) => {
    if (timer.current) clearTimeout(timer.current);
    // New input makes the request in flight stale at once, not only when the debounce fires
    requestId.current += 1;
    const current = requestId.current;
    timer.current = setTimeout(() => {
      setLoading(true);
      fetchQuery(defenseThreatsFieldSearchQuery, { types: DEFENSE_THREAT_TYPES, search: input, first: SEARCH_SIZE })
        .toPromise()
        .then((data) => {
          if (current !== requestId.current) return;
          const edges = (data as DefenseThreatsFieldSearchQuery$data | undefined)?.stixDomainObjects?.edges ?? [];
          setOptions(edges.map(({ node }) => ({ value: node.id, label: node.representative.main, type: node.entity_type })));
        })
        .catch(() => {
          // Options of an earlier input are never shown as the results of a failed search
          if (current === requestId.current) setOptions([]);
        })
        .finally(() => {
          if (current === requestId.current) setLoading(false);
        });
    }, SEARCH_DEBOUNCE_MS);
  };

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  return (
    <Combobox<DefenseThreatOption>
      multiple
      labelPosition="none"
      className="w-full"
      options={options}
      value={value.filter((threat) => confirmedIds.has(threat.value))}
      loading={loading}
      getOptionLabel={(option) => option.label}
      isOptionEqualToValue={(option, other) => option.value === other.value}
      filterOptions={(all) => all}
      onInputChange={(input) => search(input)}
      onOpenChange={(open) => {
        if (open && options.length === 0) search('');
      }}
      onValueChange={(next) => {
        const threats = (next as DefenseThreatOption[] | null) ?? [];
        setConfirmedIds((current) => new Set([...current, ...threats.map((threat) => threat.value)]));
        onChange(threats);
      }}
      renderOption={(option) => (
        <span style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          <ItemIcon type={option.type} />
          {option.label}
        </span>
      )}
    >
      <ComboboxField>
        <ComboboxChips aria-label={t_i18n('Threats')} />
        <ComboboxInput placeholder={t_i18n('Threats')} aria-label={t_i18n('Threats')} data-testid="defense-threats-input" />
        <ComboboxControls>
          <ComboboxClear />
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent
        emptyMessage={t_i18n('No available options')}
        loadingMessage={t_i18n('Loading')}
        listAriaLabel={t_i18n('Threats')}
      />
    </Combobox>
  );
};

export default DefenseThreatsField;
