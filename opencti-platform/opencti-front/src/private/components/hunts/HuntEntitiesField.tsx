import React, { CSSProperties, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { Field } from 'formik';
import { useTheme } from '@mui/styles';
import { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../components/ComboboxField';
import ItemIcon from '../../../components/ItemIcon';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { fetchQuery } from '../../../relay/environment';
import { FieldOption } from '../../../utils/field';
import { HuntEntitiesFieldSearchQuery$data } from './__generated__/HuntEntitiesFieldSearchQuery.graphql';

const huntEntitiesFieldSearchQuery = graphql`
  query HuntEntitiesFieldSearchQuery($search: String, $types: [String]) {
    stixCoreObjects(search: $search, types: $types, first: 50) {
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

interface HuntEntitiesFieldProps {
  name: string;
  label: string;
  types: string[];
  helpertext?: string;
  disabled?: boolean;
  style?: CSSProperties;
}

/**
 * Picks the knowledge of a hunt (platforms, threats, techniques, indicators...) of the given types. The library
 * Combobox keeps its panel in the layer stack of the dialogs and drawers of the hunts, which a portalled MUI popper
 * inside a modal dialog does not.
 */
const HuntEntitiesField = ({ name, label, types, helpertext, disabled = false, style }: HuntEntitiesFieldProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [options, setOptions] = useState<FieldOption[]>([]);
  const [loading, setLoading] = useState(false);
  const latestSearch = useRef(0);

  const search = (text: string) => {
    latestSearch.current += 1;
    const current = latestSearch.current;
    setLoading(true);
    fetchQuery(huntEntitiesFieldSearchQuery, { search: text, types })
      .toPromise()
      .then((data) => {
        if (current !== latestSearch.current) return;
        const edges = (data as HuntEntitiesFieldSearchQuery$data | undefined)?.stixCoreObjects?.edges ?? [];
        setOptions(edges.flatMap((edge) => (edge?.node ? [{
          value: edge.node.id,
          label: edge.node.representative.main,
          type: edge.node.entity_type,
        }] : [])));
      })
      .catch(() => undefined)
      .finally(() => {
        if (current === latestSearch.current) setLoading(false);
      });
  };

  return (
    <Field
      component={ComboboxField}
      name={name}
      label={label}
      helperText={helpertext}
      multiple
      disabled={disabled}
      style={style}
      options={options}
      loading={loading}
      noOptionsText={t_i18n('No available options')}
      loadingText={t_i18n('Loading')}
      filterOptions={(current: FieldOption[]) => current}
      groupBy={types.length > 1 ? (option: FieldOption) => t_i18n(`entity_${option.type}`) : undefined}
      onFocusInput={() => search('')}
      onInputChange={(text: string, meta: ComboboxChangeMeta) => {
        if (meta.cause === 'type') search(text);
      }}
      renderOption={(option: FieldOption) => (
        <span style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), minWidth: 0 }}>
          <ItemIcon type={option.type} />
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{option.label}</span>
        </span>
      )}
    />
  );
};

export default HuntEntitiesField;
