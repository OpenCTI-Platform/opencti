import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { CountryFieldSearchQuery$data } from '@components/common/form/__generated__/CountryFieldSearchQuery.graphql';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { Option } from './ReferenceField';

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

interface CountryFieldProps {
  id: string;
  name: string;
  label: string;
  onChange?: (name: string, value: Option) => void;
  containerStyle?: Record<string, string | number>;
  helpertext?: string;
  required?: boolean;
}

const CountryFieldQuery = graphql`
  query CountryFieldSearchQuery($search: String) {
    countries(search: $search) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const CountryField: FunctionComponent<CountryFieldProps> = ({
  id,
  name,
  label,
  containerStyle,
  onChange,
  helpertext,
  required = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [countries, setCountries] = useState<
  {
    label: string | undefined;
    value: string | undefined;
  }[]
  >([]);

  const searchCountries = (event: React.ChangeEvent<HTMLInputElement>) => {
    fetchQuery(CountryFieldQuery, {
      search: event && event.target.value ? event.target.value : '',
    })
      .toPromise()
      .then((data) => {
        const NewCountries = (
          (data as CountryFieldSearchQuery$data)?.countries?.edges ?? []
        ).map((n) => ({
          label: n?.node.name,
          value: n?.node.id,
        }));
        const templateValues = [...countries, ...NewCountries];
        // Keep only the unique list of options
        const uniqTemplates = templateValues.filter((item, index) => {
          return (
            templateValues.findIndex((e) => e.value === item.value) === index
          );
        });
        setCountries(uniqTemplates);
      });
  };

  return (
    <div style={{ width: '100%' }}>
      <Field
        id={id}
        component={AutocompleteField}
        name={name}
        required={required}
        textfieldprops={{
          variant: 'standard',
          label: t_i18n(label),
          helperText: helpertext,
          onFocus: searchCountries,
          required,
        }}
        onChange={onChange}
        style={containerStyle}
        noOptionsText={t_i18n('No available options')}
        options={countries}
        onInputChange={searchCountries}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: { color: string; label: string },
        ) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <ItemIcon type="Country" />
            </div>
            <div className={classes.text}>{option.label ?? ''}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
    </div>
  );
};

export default CountryField;
