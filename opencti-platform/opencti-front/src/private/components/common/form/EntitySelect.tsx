import { Checkbox } from '@mui/material';
import {
  Combobox,
  ComboboxChips,
  type ComboboxChangeMeta,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
} from '@filigran/design-system';
import React, { Suspense, useEffect, useTransition } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { useTheme } from '@mui/styles';
import { EntitySelectSearchQuery, FilterMode, FilterOperator } from './__generated__/EntitySelectSearchQuery.graphql';
import useDebounceCallback from '../../../../utils/hooks/useDebounceCallback';
import Loader from '../../../../components/Loader';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption } from '../../../../utils/field';

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
  type: string;
};

interface EntitySelectBaseProps {
  label: string;

  onInputChange: (val: string) => void;
  queryRef: PreloadedQuery<EntitySelectSearchQuery>;
}

interface EntitySelectComponentProps extends EntitySelectBaseProps {
  multiple: boolean;
  value: EntityOption | EntityOption[] | null;
  onChange?: (val: EntityOption | EntityOption[] | null) => void;
}

const EntitySelectComponent = ({
  label,
  value,

  multiple = false,
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
    <Combobox<EntityOption>
      value={value}
      options={options}
      multiple={multiple}
      // MUI's disableCloseOnSelect is the library's closeOnSelect inverted, and
      // the library already defaults it to false in multiple mode.
      closeOnSelect={!multiple}
      isOptionEqualToValue={(option, val) => option.value === val.value}
      getOptionLabel={(option) => option?.label ?? ''}
      onInputChange={(val: string, meta: ComboboxChangeMeta) => {
        if (meta.cause === 'type') throttleSearch(val);
      }}
      onValueChange={(next) => onChange?.(next)}
      renderOption={(option) => (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: theme.spacing(1.5),
          width: '100%',
        }}
        >
          {multiple && (
            <Checkbox
              checked={!!(value as EntityOption[]).find((v) => option.value === v.value)}
            />
          )}
          <ItemIcon type={option.type} />
          <span style={{
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
          >
            {option.label}
          </span>
        </div>
      )}
    >
      <ComboboxLabel>{label}</ComboboxLabel>
      <ComboboxField>
        {/* renderTags is gone: chips come from getOptionLabel, so the 50-char
            truncation goes with it — the same removal as the other chip fields,
            since one label function now serves the chip, the input and the
            filter. */}
        {multiple && <ComboboxChips aria-label={label} />}
        <ComboboxInput />
        <ComboboxControls>
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent
        emptyMessage={t_i18n('No available options')}
        listAriaLabel={label}
      />
    </Combobox>
  );
};

type EntitySelectProps = Omit<EntitySelectComponentProps, 'onInputChange' | 'queryRef'> & {
  types: string[];
};

const EntitySelect = ({ types, ...otherProps }: EntitySelectProps) => {
  const [, startTransition] = useTransition();
  const [queryRef, loadQuery] = useQueryLoader<EntitySelectSearchQuery>(entitySelectSearchQuery);

  const search = (search: string) => loadQuery({
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
  }, { fetchPolicy: 'store-and-network' });

  // Initial load
  useEffect(() => {
    search('');
  }, []);

  const handleSearchChange = (val: string) => {
    startTransition(() => {
      search(val);
    });
  };

  return (
    <Suspense fallback={<Loader />}>
      {queryRef && (
        <EntitySelectComponent
          {...otherProps}
          onInputChange={handleSearchChange}
          queryRef={queryRef}
        />
      )}
    </Suspense>
  );
};

export default EntitySelect;
