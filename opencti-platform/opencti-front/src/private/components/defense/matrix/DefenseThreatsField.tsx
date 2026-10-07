import React, { useEffect, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { Combobox, ComboboxChips, ComboboxClear, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput, ComboboxTrigger } from '@filigran/design-system';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import ItemIcon from '../../../../components/ItemIcon';
import { DEFENSE_THREAT_TYPES, type DefenseThreatOption } from './defenseMatrix-utils';
import { DefenseThreatsFieldSearchQuery$data } from './__generated__/DefenseThreatsFieldSearchQuery.graphql';
import { DefenseThreatsFieldAccessQuery$data } from './__generated__/DefenseThreatsFieldAccessQuery.graphql';

const SEARCH_DEBOUNCE_MS = 300;
const SEARCH_SIZE = 25;
const NO_CONFIRMED_IDS: ReadonlySet<string> = new Set();
const NO_OPTIONS: DefenseThreatOption[] = [];

interface Confirmations {
  userId: string;
  ids: ReadonlySet<string>;
}

interface SearchResults {
  userId: string;
  options: DefenseThreatOption[];
}

const withConfirmed = (current: Confirmations, userId: string, ids: Iterable<string>): Confirmations => ({
  userId,
  ids: new Set([...(current.userId === userId ? current.ids : []), ...ids]),
});

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
  const { me } = useAuth();
  // The search results belong to the account that searched: another account never sees them
  const [results, setResults] = useState<SearchResults>(() => ({ userId: me.id, options: NO_OPTIONS }));
  const options = results.userId === me.id ? results.options : NO_OPTIONS;
  const [loading, setLoading] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const requestId = useRef(0);
  // A threat of the stored scope is shown only once the reader is known to access it: the threats picked from the search
  // are, the others are confirmed by one query, which also drops the threats no longer accessible and refreshes the names.
  // The confirmations belong to the account: another account confirms its own stored threats.
  const [confirmed, setConfirmed] = useState<Confirmations>(() => ({ userId: me.id, ids: NO_CONFIRMED_IDS }));
  const confirmedIds = confirmed.userId === me.id ? confirmed.ids : NO_CONFIRMED_IDS;
  const latest = useRef({ value, onChange });
  latest.current = { value, onChange };
  const unconfirmedKey = value.filter((threat) => !confirmedIds.has(threat.value)).map((threat) => threat.value).join(',');

  useEffect(() => {
    if (!unconfirmedKey) return undefined;
    const unconfirmedIds = unconfirmedKey.split(',');
    const userId = me.id;
    // Cancelled when the account changes too: an answer for the previous account is dropped
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
        setConfirmed((current) => withConfirmed(current, userId, accessible.keys()));
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
  }, [unconfirmedKey, me.id]);

  const search = (input: string) => {
    if (timer.current) clearTimeout(timer.current);
    // New input makes the request in flight stale at once, not only when the debounce fires
    requestId.current += 1;
    const current = requestId.current;
    const userId = me.id;
    timer.current = setTimeout(() => {
      setLoading(true);
      fetchQuery(defenseThreatsFieldSearchQuery, { types: DEFENSE_THREAT_TYPES, search: input, first: SEARCH_SIZE })
        .toPromise()
        .then((data) => {
          if (current !== requestId.current) return;
          const edges = (data as DefenseThreatsFieldSearchQuery$data | undefined)?.stixDomainObjects?.edges ?? [];
          setResults({ userId, options: edges.map(({ node }) => ({ value: node.id, label: node.representative.main, type: node.entity_type })) });
        })
        .catch(() => {
          // Options of an earlier input are never shown as the results of a failed search
          if (current === requestId.current) setResults({ userId, options: NO_OPTIONS });
        })
        .finally(() => {
          if (current === requestId.current) setLoading(false);
        });
    }, SEARCH_DEBOUNCE_MS);
  };

  // Another account makes the pending and in-flight searches stale: their answers are for the previous account
  useEffect(() => {
    if (timer.current) clearTimeout(timer.current);
    requestId.current += 1;
    setLoading(false);
  }, [me.id]);

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
        setConfirmed((current) => withConfirmed(current, me.id, threats.map((threat) => threat.value)));
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
