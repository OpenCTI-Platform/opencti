import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Field } from 'formik';
import { CsvMapperFieldSearchQuery } from '@components/common/form/__generated__/CsvMapperFieldSearchQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import ComboboxField from '../../../../components/ComboboxField';
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
}));

export type CsvMapperFieldOption = FieldOption & { representations: { attributes: { key: string; default_values: { name: string }[] | string[] }[] }[] };
interface CsvMapperFieldComponentProps {
  name: string;
  isOptionEqualToValue: (option: FieldOption, value: FieldOption) => boolean;
  onChange?: (name: string, value: CsvMapperFieldOption) => void;
  queryRef: PreloadedQuery<CsvMapperFieldSearchQuery>;
  required?: boolean;
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
  required = false,
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
        component={ComboboxField}
        // MUI hid its clear indicator here with display:none; the library defaults
        // clearable to true, so the affordance must be declined explicitly.
        style={fieldSpacingContainerStyle}
        name={name}
        multiple={false}
        label={t_i18n('CSV Mappers')}
        required={required}
        noOptionsText={t_i18n('No available options')}
        options={csvMappersPreloaded}
        isOptionEqualToValue={isOptionEqualToValue}
        onChange={onChange}
        renderOption={(option: FieldOption) => (
          <>
            <div className={classes.icon} style={{ color: option.color }}>
              <ItemIcon type="csvmapper" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </>
        )}
      />
    </>
  );
};

export default CsvMapperField;
