import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import type { Theme } from '../../../../../../components/Theme';
import { fetchQuery } from '../../../../../../relay/environment';
import { useFormatter } from '../../../../../../components/i18n';
import useAuth from '../../../../../../utils/hooks/useAuth';
import AutocompleteField from '../../../../../../components/AutocompleteField';
import ItemIcon from '../../../../../../components/ItemIcon';
import { FieldOption } from '../../../../../../utils/field';
import { PlaybookFlowFieldRunAsQuery$data } from './__generated__/PlaybookFlowFieldRunAsQuery.graphql';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
}));

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
  const classes = useStyles();
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
        const serviceAccounts = (
          (data as PlaybookFlowFieldRunAsQuery$data)?.members?.edges ?? []
        ).map((edge) => ({
          label: edge?.node.name,
          value: edge?.node.id,
          type: edge?.node.entity_type,
        })) as OptionRunAs[];
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
            <div className={classes.icon}>
              <ItemIcon type={option.type} />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
      />
    </div>
  );
};

export default PlaybookFlowFieldRunAs;
