import { Option } from '@components/common/form/ReferenceField';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Field } from 'formik';
import { CsvMapperFieldSearchQuery } from '@components/common/form/__generated__/CsvMapperFieldSearchQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
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

export type CsvMapperFieldOption = Option & { representations: { attributes: { key: string, default_values: { name: string }[] | string[] }[] }[] };
interface CsvMapperFieldComponentProps {
  name: string;
  isOptionEqualToValue: (option: Option, value: Option) => boolean;
  onChange?: (name: string, value: CsvMapperFieldOption) => void;
  queryRef: PreloadedQuery<CsvMapperFieldSearchQuery>
}

export const csvMapperQuery = graphql`
  query CsvMapperFieldSearchQuery($search: String) {
    csvMappers(search: $search) {
      edges {
        node {
          id
          name
          representations {
            attributes {
              key
              default_values {
                name
              }
            }
          }
        }
      }
    }
  }
`;

const CsvMapperField: FunctionComponent<CsvMapperFieldComponentProps> = ({
  onChange,
  isOptionEqualToValue,
  name,
  queryRef,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(csvMapperQuery, queryRef);
  const csvMappersPreloaded = (data?.csvMappers?.edges || []).map(({ node }) => ({
    value: node.id,
    label: node.name,
    representations: node.representations,
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
          label: t_i18n('CSV Mappers'),
        }}
        noOptionsText={t_i18n('No available options')}
        options={csvMappersPreloaded}
        isOptionEqualToValue={isOptionEqualToValue}
        onChange={onChange}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: Option,
        ) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <ItemIcon type="csvmapper" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
      />
    </>
  );
};

export default CsvMapperField;
