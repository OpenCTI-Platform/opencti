import { Option } from '@components/common/form/ReferenceField';
import { graphql } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Field } from 'formik';
import * as R from 'ramda';
import { CsvMapperFieldSearchQuery$data } from '@components/common/form/__generated__/CsvMapperFieldSearchQuery.graphql';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ItemIcon from '../../../../components/ItemIcon';

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

interface CsvMapperFieldComponentProps {
  name: string;
  onChange?: (name: string, value: Option) => void;
}

const CsvMapperQuery = graphql`
  query CsvMapperFieldSearchQuery($search: String) {
    csvMappers(search: $search) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const CsvMapperField: FunctionComponent<CsvMapperFieldComponentProps> = ({
  onChange,
  name,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [csvMappers, setCsvMappers] = useState<
  {
    label: string | undefined;
    value: string | undefined;
  }[]
  >([]);
  const searchCsvMappers = (event: React.ChangeEvent<HTMLInputElement>) => {
    const search = event?.target?.value ?? '';
    fetchQuery(CsvMapperQuery, { search })
      .toPromise()
      .then((data) => {
        const newCsvMappers = (
          (data as CsvMapperFieldSearchQuery$data)?.csvMappers?.edges ?? []
        ).map(({ node }) => ({
          value: node.id,
          label: node.name,
        }));
        setCsvMappers(R.uniq([...csvMappers, ...newCsvMappers]));
      });
  };
  return (
    <>
      <Field
        component={AutocompleteField}
        style={fieldSpacingContainerStyle}
        name={name}
        multiple={true}
        textfieldprops={{
          variant: 'standard',
          label: t('Csv Mappers'),
          onFocus: searchCsvMappers,
        }}
        noOptionsText={t('No available options')}
        options={csvMappers}
        onInputChange={searchCsvMappers}
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
