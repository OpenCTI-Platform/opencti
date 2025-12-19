import React, { FunctionComponent, ReactNode, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import { Link } from 'react-router-dom';
import { OpenInNewOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { CreatorFieldSearchQuery$data } from './__generated__/CreatorFieldSearchQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { FieldOption } from '../../../../utils/field';

interface CreatorFieldProps {
  name: string;
  label: string;
  onChange?: (name: string, value: FieldOption) => void;
  containerStyle?: Record<string, string | number>;
  showConfidence?: boolean;
  helpertext?: string;
  required?: boolean;
  disabled?: boolean;
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

type CreatorNode = NonNullable<CreatorFieldSearchQuery$data['members']>['edges'][number]['node'];

type CreatorOption = FieldOption & {
  extra?: ReactNode;
};

const CreatorField: FunctionComponent<CreatorFieldProps> = ({
  name,
  label,
  containerStyle,
  onChange,
  showConfidence = false,
  disabled = false,
}) => {
  const { t_i18n } = useFormatter();
  const isGrantedToUsers = useGranted([SETTINGS_SETACCESSES]);
  const [creatorOptions, setCreatorOptions] = useState<CreatorOption[]>([]);

  const getExtraFromNode = (node?: CreatorNode) => {
    if (showConfidence && node?.effective_confidence_level) {
      let textToShow = `${t_i18n('Max Confidence')} ${node.effective_confidence_level.max_confidence}`;
      if (node?.effective_confidence_level.overrides?.length) {
        const overrides = t_i18n(
          '',
          { id: '+ N override(s)', values: { count: node.effective_confidence_level.overrides.length } },
        );
        textToShow = `${textToShow} ${overrides}`;
      }
      if (isGrantedToUsers) {
        return (
          <span>
            {textToShow}
            <IconButton
              component={Link}
              to={`/dashboard/settings/accesses/users/${node.id}`}
              sx={{ marginLeft: 1 }}
              color="primary"
            >
              <OpenInNewOutlined fontSize="small" />
            </IconButton>
          </span>
        );
      }
      return textToShow;
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
        disabled={disabled}
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
          <li {...props}>
            <div
              style={{
                paddingTop: 4,
                color: option.color,
              }}
            >
              <ItemIcon type="user" />
            </div>
            <div
              style={{
                flexGrow: 1,
                marginLeft: 10,
              }}
            >
              {option.label}
            </div>
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
