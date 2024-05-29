import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { CreatorFieldSearchQuery$data } from './__generated__/CreatorFieldSearchQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import { Option } from './ReferenceField';

interface CreatorFieldProps {
  name: string;
  label: string;
  onChange?: (name: string, value: Option) => void;
  containerStyle?: Record<string, string | number>;
  showConfidence?: boolean;
}

const CreatorFieldQuery = graphql`
  query CreatorFieldSearchQuery($search: String) {
    members(search: $search, entityTypes: [User]) {
      edges {
        node {
          id
          name
          entity_type
          effective_confidence_level {
            max_confidence
            overrides {
              entity_type
              max_confidence
            }
          }
        }
      }
    }
  }
`;

type CreatorNode = {
  readonly effective_confidence_level: {
    readonly max_confidence: number;
    readonly overrides: ReadonlyArray<{
      readonly entity_type: string;
      readonly max_confidence: number;
    }>;
  } | null | undefined;
  readonly entity_type: string;
  readonly id: string;
  readonly name: string;
};

type CreatorOption = Option & {
  extra?: string | null,
};

const CreatorField: FunctionComponent<CreatorFieldProps> = ({
  name,
  label,
  containerStyle,
  onChange,
  showConfidence = false,
}) => {
  const { t_i18n } = useFormatter();
  const [creatorOptions, setCreatorOptions] = useState<CreatorOption[]>([]);

  const getExtraFromNode = (node?: CreatorNode) => {
    if (showConfidence && node?.effective_confidence_level) {
      const confidence = `${t_i18n('Max confidence')} ${node.effective_confidence_level.max_confidence}`;
      if (node?.effective_confidence_level.overrides?.length) {
        const overrides = t_i18n(
          '',
          { id: '+ N override(s)', values: { count: node.effective_confidence_level.overrides.length } },
        );
        return `${confidence} ${overrides}`;
      }
      return confidence;
    }
    return null;
  };

  const searchCreators = (event: React.ChangeEvent<HTMLInputElement>) => {
    fetchQuery(CreatorFieldQuery, {
      search: event && event.target.value ? event.target.value : '',
    })
      .toPromise()
      .then((data) => {
        const NewCreators = (
          (data as CreatorFieldSearchQuery$data)?.members?.edges ?? []
        ).map((n) => ({
          label: n?.node.name ?? t_i18n('Unknown'),
          value: n?.node.id,
          extra: getExtraFromNode(n?.node),
        }));
        const templateValues = [...creatorOptions, ...NewCreators];
        // Keep only the unique list of options
        const uniqTemplates = templateValues.filter((item, index) => {
          return (
            templateValues.findIndex((e) => e.value === item.value) === index
          );
        });
        setCreatorOptions(uniqTemplates);
      });
  };
  return (
    <div style={{ width: '100%' }}>
      <Field
        component={AutocompleteField}
        name={name}
        textfieldprops={{
          variant: 'standard',
          label,
          onFocus: searchCreators,
        }}
        disableClearable
        onChange={onChange}
        style={containerStyle}
        noOptionsText={t_i18n('No available options')}
        options={creatorOptions}
        isOptionEqualToValue={(option: CreatorOption, selected: CreatorOption) => option.value === selected.value}
        onInputChange={searchCreators}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: CreatorOption,
        ) => (
          <li {...props} >
            <Box
              sx={{
                paddingTop: 1,
                color: option.color,
              }}
            >
              <ItemIcon type="user"/>
            </Box>
            <Box
              sx={{
                flexGrow: 1,
                marginLeft: 1,
              }}
            >
              {option.label}
            </Box>
            {option.extra && (
              <Box
                sx={{
                  flexGrow: 1,
                  marginLeft: 1,
                  textAlign: 'right',
                  color: 'text.disabled',
                }}
              >
                {option.extra}
              </Box>
            )}
          </li>
        )}

      />
    </div>
  );
};

export default CreatorField;
