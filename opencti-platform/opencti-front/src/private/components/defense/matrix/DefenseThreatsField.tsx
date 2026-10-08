import React, { useEffect, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import {
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxHelperText,
  ComboboxInput,
  ComboboxTrigger,
} from '@filigran/design-system';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import ItemIcon from '../../../../components/ItemIcon';
import { DEFENSE_MAX_SELECTED_THREATS, DEFENSE_THREAT_TYPES, type DefenseThreatOption } from './defenseMatrix-utils';
import { DefenseThreatsFieldSearchQuery$data } from './__generated__/DefenseThreatsFieldSearchQuery.graphql';

const SEARCH_DEBOUNCE_MS = 300;
const SEARCH_SIZE = 25;
const NO_OPTIONS: DefenseThreatOption[] = [];

interface SearchResults {
  userId: string;
  options: DefenseThreatOption[];
}

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
  // The threats of the scope in use, all known to be accessible to the reader (see useDefenseScope)
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
  const atLimit = value.length >= DEFENSE_MAX_SELECTED_THREATS;

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
      value={value}
      loading={loading}
      getOptionLabel={(option) => option.label}
      isOptionEqualToValue={(option, other) => option.value === other.value}
      isOptionDisabled={(option) => atLimit && !value.some((threat) => threat.value === option.value)}
      filterOptions={(all) => all}
      onInputChange={(input) => search(input)}
      onOpenChange={(open) => {
        if (open && options.length === 0) search('');
      }}
      onValueChange={(next) => onChange((next as DefenseThreatOption[] | null) ?? [])}
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
      {atLimit && (
        <ComboboxHelperText data-testid="defense-threats-limit">
          {t_i18n('At most {count} threats can be selected: remove one to select another', { values: { count: DEFENSE_MAX_SELECTED_THREATS } })}
        </ComboboxHelperText>
      )}
      <ComboboxContent
        emptyMessage={t_i18n('No available options')}
        loadingMessage={t_i18n('Loading')}
        listAriaLabel={t_i18n('Threats')}
      />
    </Combobox>
  );
};

export default DefenseThreatsField;
