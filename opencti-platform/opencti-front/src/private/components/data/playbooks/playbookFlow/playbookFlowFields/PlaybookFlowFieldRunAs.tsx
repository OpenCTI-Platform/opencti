import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import { fetchQuery } from '../../../../../../relay/environment';
import { useFormatter } from '../../../../../../components/i18n';
import useAuth from '../../../../../../utils/hooks/useAuth';
import AutocompleteField from '../../../../../../components/AutocompleteField';
import ItemIcon from '../../../../../../components/ItemIcon';
import { FieldOption } from '../../../../../../utils/field';
import { PlaybookFlowFieldRunAsQuery$data } from './__generated__/PlaybookFlowFieldRunAsQuery.graphql';

// The agent runs on behalf of the configured user, so the picker is
// deliberately restricted to identities the author is allowed to act as:
// the author themselves and any service account. Service accounts are
// fetched from the server with a dedicated filter (the generic `members`
// API is reused untouched); the current user is injected client-side from
// the auth context. The backend re-validates this on save.
const playbookFlowFieldRunAsQuery = graphql`
  query PlaybookFlowFieldRunAsQuery($search: String, $first: Int, $filters: FilterGroup) {
    members(search: $search, first: $first, entityTypes: [User], filters: $filters) {
      edges {
        node {
          id
          entity_type
          name
        }
      }
    }
  }
`;

const serviceAccountsFilter = {
  mode: 'and',
  filters: [{ key: ['user_service_account'], values: ['true'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

interface OptionRunAs extends FieldOption {
  type: string;
}

interface PlaybookFlowFieldRunAsProps {
  name: string;
  label?: string;
  style?: Record<string, string | number>;
}

const PlaybookFlowFieldRunAs: FunctionComponent<PlaybookFlowFieldRunAsProps> = ({
  name,
  label,
  style,
}) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const currentUserOption: OptionRunAs = {
    label: me.name,
    value: me.id,
    type: me.entity_type,
  };
  const [options, setOptions] = useState<OptionRunAs[]>([currentUserOption]);

  const searchRunAs = (event: React.ChangeEvent<HTMLInputElement>) => {
    const search = event && event.target.value ? event.target.value : '';
    fetchQuery(playbookFlowFieldRunAsQuery, {
      search,
      first: 50,
      filters: serviceAccountsFilter,
    })
      .toPromise()
      .then((data) => {
        // Drop any incomplete edge (relay can return a null node when an
        // item is no longer accessible) so options always carry a defined
        // value/type and `groupBy` never receives undefined.
        const serviceAccounts: OptionRunAs[] = (
          (data as PlaybookFlowFieldRunAsQuery$data)?.members?.edges ?? []
        ).flatMap((edge) => {
          const node = edge?.node;
          if (!node) return [];
          return [{ label: node.name, value: node.id, type: node.entity_type }];
        });
        // Always offer the current user, only hiding it when it does not
        // match the current search input.
        const lowerSearch = search.toLowerCase();
        const selfMatchesSearch = !lowerSearch
          || currentUserOption.label.toLowerCase().includes(lowerSearch);
        const merged = [
          ...(selfMatchesSearch ? [currentUserOption] : []),
          ...serviceAccounts,
        ];
        const uniqueOptions = merged.filter(
          (item, index) => merged.findIndex((e) => e.value === item.value) === index,
        );
        setOptions(uniqueOptions);
      });
  };

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={AutocompleteField}
        name={name}
        multiple={false}
        textfieldprops={{
          variant: 'standard',
          label: t_i18n(label ?? 'Run as'),
          helperText: t_i18n('Only yourself and service accounts can be selected'),
          onFocus: searchRunAs,
        }}
        style={style}
        noOptionsText={t_i18n('No available options')}
        options={options}
        groupBy={(option: OptionRunAs) => option.type}
        onInputChange={searchRunAs}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: OptionRunAs,
        ) => (
          <li {...props}>
            <Box sx={{ paddingTop: '4px', display: 'inline-block', color: 'primary.main' }}>
              <ItemIcon type={option.type} />
            </Box>
            <Box sx={{ display: 'inline-block', flexGrow: 1, marginLeft: '10px' }}>
              {option.label}
            </Box>
          </li>
        )}
      />
    </div>
  );
};

export default PlaybookFlowFieldRunAs;
