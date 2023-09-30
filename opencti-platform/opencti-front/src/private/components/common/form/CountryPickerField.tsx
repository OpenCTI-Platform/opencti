import { Field } from 'formik';
import { useEffect, useState } from 'react';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { getCountriesQuery } from '../../locations/countries/Country';
import { CountryGetAllQuery$data } from '../../locations/countries/__generated__/CountryGetAllQuery.graphql';

interface CountryType {
  id: string,
  name: string,
}

interface CountryPickerFieldComponentProps {
  id: string,
  name: string,
  multi: boolean,
  label: string,
  initialValues?: string[] | string,
  style?: {
    marginTop?: number;
    width?: string;
  },
  handleChange: (field: string, value: string[] | string) => void,
}

const CountryPickerFieldComponent = ({
  id,
  name,
  multi,
  label,
  initialValues = [],
  style = {},
  handleChange,
}: CountryPickerFieldComponentProps) => {
  const { t } = useFormatter();
  const [countries, setCountries] = useState<CountryType[]>([]);
  const [values, setValues] = useState<string[] | string | undefined | null>(multi ? [] : null);

  function onValueUpdate(selected: string[] | string | undefined) {
    if (typeof selected === 'undefined') {
      setValues(selected);
    } else {
      const options = Array.isArray(selected)
        ? countries.filter((country) => selected.includes(country?.id)).map((country) => t(country.name))
        : t(countries.filter((country) => country?.id === selected)?.[0]?.name);
      setValues(options);
    }
  }

  fetchQuery(getCountriesQuery, {})
    .subscribe({
      closed: false,
      error: () => {},
      complete: () => {},
      next: (data: CountryGetAllQuery$data) => {
        setCountries(data?.countries?.edges?.map(({ node }) => ({
          id: node?.id,
          name: node?.name,
        })) || []);
      },
    });

  useEffect(() => {
    if (typeof initialValues === 'undefined' || initialValues?.length <= 0) {
      setValues(multi ? [] : null);
    } else if (countries?.length > 0) {
      onValueUpdate(initialValues);
    }
  }, [countries]);

  return (
    <Field
      id={id}
      component={AutocompleteField}
      name={name}
      multiple={multi}
      textfieldprops={{
        variant: 'standard',
        label: t(label),
      }}
      value={values}
      style={style}
      noOptionsText={t('No available options')}
      options={countries}
      onChange={(fieldName: string, selected: CountryType[] | CountryType) => {
        const updated = Array.isArray(selected)
          ? selected.map((country) => country.id)
          : selected.id;
        onValueUpdate(updated);
        handleChange(fieldName, updated);
      }}
      renderOption={(optionProps: React.HTMLAttributes<HTMLLIElement>, option: CountryType) => (
        <li {...optionProps}>
          {t(option.name)}
        </li>
      )}
    />
  );
};

export default CountryPickerFieldComponent;
