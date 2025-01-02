import { Autocomplete, TextField, Tooltip } from '@mui/material';
import React, { Suspense, useMemo, useState } from 'react';
import { Option } from '@components/common/form/ReferenceField';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { EntitySelectSearchQuery, FilterMode, FilterOperator } from './__generated__/EntitySelectSearchQuery.graphql';
import useDebounceCallback from '../../../../utils/hooks/useDebounceCallback';
import Loader from '../../../../components/Loader';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';

const entitySelectSearchQuery = graphql`
  query EntitySelectSearchQuery($search: String, $filters: FilterGroup) {
    stixCoreObjects(search: $search, first: 50, filters: $filters) {
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

export type EntityOption = Pick<Option, 'label' | 'value'> & {
  type: string
};

interface EntitySelectComponentProps {
  label: string
  value: EntityOption | null
  onChange?: (val: EntityOption | null) => void
  onInputChange: (val: string) => void
  queryRef: PreloadedQuery<EntitySelectSearchQuery>
}

const EntitySelectComponent = ({
  label,
  value,
  onChange,
  onInputChange,
  queryRef,
}: EntitySelectComponentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const throttleSearch = useDebounceCallback(onInputChange, 400);
  const { stixCoreObjects } = usePreloadedQuery(entitySelectSearchQuery, queryRef);

  const options: EntityOption[] = (stixCoreObjects?.edges ?? []).map((sco) => ({
    label: sco.node.representative.main,
    value: sco.node.id,
    type: sco.node.entity_type,
  }));

  return (
    <Autocomplete
      value={value}
      options={options}
      noOptionsText={t_i18n('No available options')}
      isOptionEqualToValue={(o: EntityOption, v: EntityOption) => o.value === v.value}
      onInputChange={(_, val) => throttleSearch(val)}
      onChange={(_, val) => onChange?.(val)}
      renderInput={(params) => <TextField {...params} label={label} />}
      renderOption={(props, option) => (
        <Tooltip title={option.label}>
          <li
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: theme.spacing(1.5),
              height: theme.spacing(6),
            }}
            {...props}
          >
            <ItemIcon type={option.type} />
            <span style={{
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
            >
              {option.label}
            </span>
          </li>
        </Tooltip>
      )}
    />
  );
};

type EntitySelectProps = Omit<EntitySelectComponentProps, 'onInputChange' | 'queryRef'> & {
  types: string[]
};

const EntitySelect = ({ types, ...otherProps }: EntitySelectProps) => {
  const [search, setSearch] = useState('');

  const variables = useMemo(() => ({
    search,
    filters: {
      mode: 'and' as FilterMode,
      filterGroups: [],
      filters: [
        {
          key: ['entity_type'],
          values: types,
          operator: 'eq' as FilterOperator,
          mode: 'or' as FilterMode,
        },
      ],
    },
  }), [search]);
  const queryRef = useQueryLoading<EntitySelectSearchQuery>(
    entitySelectSearchQuery,
    variables,
  );

  return (
    <Suspense fallback={<Loader />}>
      {queryRef && (
        <EntitySelectComponent
          {...otherProps}
          onInputChange={setSearch}
          queryRef={queryRef}
        />
      )}
    </Suspense>
  );
};

export default EntitySelect;
