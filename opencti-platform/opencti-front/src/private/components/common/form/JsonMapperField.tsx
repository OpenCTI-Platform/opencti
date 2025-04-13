import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Field } from 'formik';
import { JsonMapperFieldSearchQuery } from '@components/common/form/__generated__/JsonMapperFieldSearchQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ItemIcon from '../../../../components/ItemIcon';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
}));

export type JsonMapperFieldOption = FieldOption & { representations: { attributes: { key: string, default_values: { name: string }[] | string[] }[] }[] };
interface JsonMapperFieldComponentProps {
  name: string;
  isOptionEqualToValue: (option: FieldOption, value: FieldOption) => boolean;
  onChange?: (name: string, value: JsonMapperFieldOption) => void;
  queryRef: PreloadedQuery<JsonMapperFieldSearchQuery>
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
  const classes = useStyles();
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
        component={AutocompleteField}
        style={fieldSpacingContainerStyle}
        name={name}
        multiple={false}
        textfieldprops={{
          variant: 'standard',
          label: t_i18n('JSON Mappers'),
        }}
        required={required}
        noOptionsText={t_i18n('No available options')}
        options={jsonMappersPreloaded}
        isOptionEqualToValue={isOptionEqualToValue}
        onChange={onChange}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: FieldOption,
        ) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <ItemIcon type="jsonmapper" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
      />
    </>
  );
};

export default JsonMapperField;
