import React, { useState, FunctionComponent, SyntheticEvent } from 'react';
import { graphql } from 'react-relay';
import type { SxProps } from '@mui/material';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import ItemIcon from '../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import { CustomViewPreviewEntitySelectorQuery$data } from './__generated__/CustomViewPreviewEntitySelectorQuery.graphql';

const customViewPreviewEntitySelectorQuery = graphql`
  query CustomViewPreviewEntitySelectorQuery($search: String, $type: String!) {
    stixCoreObjects(search: $search, types: [$type], first: 100) {
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

const IN_PREVIEW_SX_PROPS: SxProps = {
  '& .MuiOutlinedInput-root': {
    '& fieldset': {
      borderColor: 'designSystem.tertiary.orange.400',
    },
    '&:hover fieldset': {
      borderColor: 'designSystem.tertiary.orange.400',
    },
    '&.Mui-focused fieldset': {
      borderColor: 'designSystem.tertiary.orange.400',
    },
  },
  '& label': {
    color: 'designSystem.tertiary.orange.400',
  },
  '&:hover label': {
    color: 'designSystem.tertiary.orange.400',
  },
  '&.Mui-focused label': {
    color: 'designSystem.tertiary.orange.400',
  },
};

const fetchOptions = async (type: string, search: string = '') => {
  const data = await fetchQuery(customViewPreviewEntitySelectorQuery, {
    search,
    type: type,
  }).toPromise();
  const typedData = data as CustomViewPreviewEntitySelectorQuery$data;
  const options = (typedData.stixCoreObjects?.edges ?? []).map((edge) => edge.node)
    .map((node) => ({
      label: node.representative.main,
      value: node.id,
      entityType: node.entity_type,
    }));
  return options;
};

interface PreviewEntityOption {
  label: string;
  value: string;
  entityType: string;
}

interface CustomViewPreviewEntitySelectorProps {
  type: string;
  onPreviewEntityChange: (id: string | null) => void;
}

const CustomViewPreviewEntitySelector: FunctionComponent<CustomViewPreviewEntitySelectorProps> = ({
  type,
  onPreviewEntityChange,
}) => {
  const { t_i18n } = useFormatter();
  const [stixCoreObjects, setStixCoreObjects] = useState<PreviewEntityOption[]>([]);
  const [value, setValue] = useState<PreviewEntityOption | null>(null);

  const searchStixCoreObjects = (_event: React.SyntheticEvent | null, newInputValue?: string) => {
    fetchOptions(type, newInputValue).then((options) => {
      setStixCoreObjects([...options]);
    });
  };

  const handleChange = (
    _event: SyntheticEvent,
    value: PreviewEntityOption | null,
  ) => {
    if (!value) {
      setValue(null);
      onPreviewEntityChange(null);
      return;
    }
    setValue(value);
    onPreviewEntityChange(value.value);
  };

  return (
    <div style={{ width: '100%', maxWidth: '500px' }}>
      <Autocomplete
        renderInput={(params) => (
          <TextField
            {...params}
            size="small"
            hiddenLabel
            variant="outlined"
            label={t_i18n('Preview with current entity set to...')}
          />
        )}
        sx={value ? IN_PREVIEW_SX_PROPS : undefined}
        options={stixCoreObjects}
        noOptionsText={t_i18n('No available options')}
        onInputChange={searchStixCoreObjects}
        onChange={handleChange}
        onFocus={searchStixCoreObjects}
        renderOption={(innerProps: React.HTMLAttributes<HTMLLIElement>, option: PreviewEntityOption) => {
          return (
            <li {...innerProps} key={option.value}>
              <div style={{ paddingTop: 4, display: 'inline-block' }}>
                <ItemIcon type={option.entityType} />
              </div>
              <div style={{
                display: 'inline-block',
                flexGrow: 1,
                marginLeft: 10,
              }}
              >{option.label}
              </div>
            </li>
          );
        }}
        isOptionEqualToValue={(option: PreviewEntityOption, value: PreviewEntityOption) => option.value === value.value}
      />
    </div>
  );
};

export default CustomViewPreviewEntitySelector;
