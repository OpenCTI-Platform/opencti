import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { styled } from '@mui/material/styles';
import { Field } from 'formik';
import { JsonMapperFieldSearchQuery } from '@components/common/form/__generated__/JsonMapperFieldSearchQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import ComboboxField from '../../../../components/ComboboxField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ItemIcon from '../../../../components/ItemIcon';

const OptionIcon = styled('div')({
  paddingTop: 4,
  display: 'inline-block',
});

const OptionText = styled('div')({
  display: 'inline-block',
  flexGrow: 1,
  marginLeft: 10,
});

export type JsonMapperFieldOption = FieldOption & { representations: { attributes: { key: string; default_values: { name: string }[] | string[] }[] }[] };
interface JsonMapperFieldComponentProps {
  name: string;
  isOptionEqualToValue: (option: FieldOption, value: FieldOption) => boolean;
  onChange?: (name: string, value: JsonMapperFieldOption) => void;
  queryRef: PreloadedQuery<JsonMapperFieldSearchQuery>;
  required?: boolean;
}

export const jsonMapperQuery = graphql`
  query JsonMapperFieldSearchQuery($search: String) {
    jsonMappers(search: $search) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const JsonMapperField: FunctionComponent<JsonMapperFieldComponentProps> = ({
  onChange,
  isOptionEqualToValue,
  name,
  queryRef,
  required = false,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(jsonMapperQuery, queryRef);
  const jsonMappersPreloaded = (data?.jsonMappers?.edges || []).map(({ node }) => ({
    value: node.id,
    label: node.name,
    representations: [],
  }));
  return (
    <>
      <Field
        component={ComboboxField}
        // MUI hid its clear indicator here with display:none; the library defaults
        // clearable to true, so the affordance must be declined explicitly.
        style={fieldSpacingContainerStyle}
        name={name}
        multiple={false}
        label={t_i18n('JSON Mappers')}
        required={required}
        noOptionsText={t_i18n('No available options')}
        options={jsonMappersPreloaded}
        isOptionEqualToValue={isOptionEqualToValue}
        onChange={onChange}
        renderOption={(option: FieldOption) => (
          <>
            <OptionIcon style={{ color: option.color }}>
              <ItemIcon type="jsonmapper" />
            </OptionIcon>
            <OptionText>{option.label}</OptionText>
          </>
        )}
      />
    </>
  );
};

export default JsonMapperField;
