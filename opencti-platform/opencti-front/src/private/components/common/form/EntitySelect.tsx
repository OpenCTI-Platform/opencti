import { Autocomplete, Chip, TextField, TextFieldProps, TextFieldVariants, Tooltip } from '@mui/material';
import React, { Suspense, useMemo, useRef, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { EntitySelectSearchQuery, FilterMode, FilterOperator } from './__generated__/EntitySelectSearchQuery.graphql';
import useDebounceCallback from '../../../../utils/hooks/useDebounceCallback';
import Loader from '../../../../components/Loader';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption } from '../../../../utils/field';
import { truncate } from '../../../../utils/String';

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

export type EntityOption = Pick<FieldOption, 'label' | 'value'> & {
  type: string
};

interface EntitySelectBaseProps {
  label: string
  variant?: TextFieldVariants
  size?: TextFieldProps['size']
  onInputChange: (val: string) => void
  queryRef: PreloadedQuery<EntitySelectSearchQuery>
}

interface SingleSelectProps extends EntitySelectBaseProps {
  multiple?: false
  value: EntityOption | null
  onChange?: (val: EntityOption | null) => void
}

interface MultiSelectProps extends EntitySelectBaseProps {
  multiple: true
  value: EntityOption[]
  onChange?: (val: EntityOption[]) => void
}

type EntitySelectComponentProps = SingleSelectProps | MultiSelectProps;

const EntitySelectComponent = ({
  label,
  value,
  variant,
  size,
  multiple = false,
  onChange,
  onInputChange,
  queryRef,
}: EntitySelectComponentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const throttleSearch = useDebounceCallback(onInputChange, 400);
  const { stixCoreObjects } = usePreloadedQuery(entitySelectSearchQuery, queryRef);
  const inputRef = useRef<HTMLInputElement>(null);

  const options: EntityOption[] = (stixCoreObjects?.edges ?? []).map((sco) => ({
    label: sco.node.representative.main,
    value: sco.node.id,
    type: sco.node.entity_type,
  }));

  const handleChange = (
    _: React.SyntheticEvent,
    newValue: EntityOption | EntityOption[] | null,
  ) => {
    if (multiple) {
      onChange?.(newValue as EntityOption[]);
    } else {
      onChange?.(newValue as EntityOption | null);
      // Remove focus after selection in single select mode
      if (inputRef.current) {
        inputRef.current.blur();
      }
    }
  };

  return (
    <Autocomplete
      value={value}
      options={options}
      multiple={multiple}
      noOptionsText={t_i18n('No available options')}
      isOptionEqualToValue={(option, val) => option.value === val.value}
      onInputChange={(_, val) => throttleSearch(val)}
      onChange={handleChange}
      renderInput={(params) => (
        <TextField
          {...params}
          variant={variant}
          size={size}
          label={label}
          inputRef={inputRef}
        />
      )}
      renderOption={(props, option) => (
        <Tooltip title={option.label} key={option.value}>
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
      renderTags={(values, getTagProps) => (
        values.map((option, index) => (
          <Chip
            {...getTagProps({ index })}
            key={option.value}
            label={truncate(option.label, 50)}
            size="small"
            style={{
              marginBlock: 0,
              marginInline: 3,
            }}
          />
        ))
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
  }), [search, types]);

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
