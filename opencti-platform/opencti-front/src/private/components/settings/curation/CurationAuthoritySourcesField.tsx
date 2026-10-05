import { useEffect, useState } from 'react';
import { Field } from 'formik';
import { identitySearchIdentitiesSearchQuery } from '@components/common/identities/IdentitySearch';
import { useFormatter } from '../../../../components/i18n';
import ComboboxField from '../../../../components/ComboboxField';
import { fetchQuery } from '../../../../relay/environment';
import { FieldOption } from '../../../../utils/field';

/** A field authority source as an option: its value is `<source_type>:<source_id>`. */
export interface AuthoritySourceOption extends FieldOption {
  source_type: 'author' | 'connector';
  source_id: string;
}

export const toAuthoritySourceOption = (
  sourceType: 'author' | 'connector',
  sourceId: string,
  name: string | null | undefined,
  prefix: string,
): AuthoritySourceOption => ({
  value: `${sourceType}:${sourceId}`,
  label: `${prefix}: ${name ?? sourceId}`,
  source_type: sourceType,
  source_id: sourceId,
});

interface IdentityNode {
  id: string;
  name: string;
}

interface CurationAuthoritySourcesFieldProps {
  name: string;
  connectors: AuthoritySourceOption[];
}

/** Ordered sources of a field authority rule, most authoritative first: connectors and author identities. */
const CurationAuthoritySourcesField = ({ name, connectors }: CurationAuthoritySourcesFieldProps) => {
  const { t_i18n } = useFormatter();
  const [search, setSearch] = useState('');
  const [authors, setAuthors] = useState<AuthoritySourceOption[]>([]);

  useEffect(() => {
    let active = true;
    const timer = setTimeout(() => {
      fetchQuery(identitySearchIdentitiesSearchQuery, { types: ['Organization', 'Individual', 'System'], search, first: 50 })
        .toPromise()
        .then((data) => {
          if (!active) return;
          const edges = ((data as { identities?: { edges?: Array<{ node: IdentityNode }> } })?.identities?.edges ?? []);
          setAuthors(edges.map(({ node }) => toAuthoritySourceOption('author', node.id, node.name, t_i18n('Author'))));
        })
        .catch(() => {
          // A failed search offers the connectors only; the next keystroke searches again.
          if (active) setAuthors([]);
        });
    }, 300);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [search]);

  return (
    <Field
      component={ComboboxField}
      name={name}
      multiple={true}
      label={t_i18n('Sources, most authoritative first')}
      options={[...connectors, ...authors]}
      groupBy={(option: AuthoritySourceOption) => (option.source_type === 'connector' ? t_i18n('Connectors') : t_i18n('Authors'))}
      onInputChange={(value: string) => setSearch(value)}
      noOptionsText={t_i18n('No available options')}
      style={{ width: '100%' }}
    />
  );
};

export default CurationAuthoritySourcesField;
