import React, { Suspense } from 'react';
import { Field } from 'formik';
import { assoc, compose, map, pipe, prop, sortBy, toLower } from 'ramda';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../components/i18n';
import SelectField from '../../../components/fields/SelectField';
import { stixCyberObservablesLinesSubTypesQuery } from './stix_cyber_observables/StixCyberObservablesLines';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { StixCyberObservablesLinesSubTypesQuery } from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservablesLinesSubTypesQuery.graphql';

interface TypesFieldComponentProps {
  queryRef: PreloadedQuery<StixCyberObservablesLinesSubTypesQuery>;
  // type: string | string [];
  name: string;
  label?: string;
  required?: boolean;
  // variant?: string;
  containerStyle?: Record<string, string | number>;
  editContext?: unknown;
  // disabled?: boolean;
  // multiple?: boolean;
  // disabledOptions?: string[];
  // // onFocus?: (name: string, value: TypesFieldOption) => void;
  // onChange?: (name: string, value: string | string[]) => void;
  // onSubmit?: (name: string, value: string | string[]) => void;
}
const TypesFieldComponent = ({
  name,
  label,
  // type,
  required = false,
  // variant,
  // onChange,
  // onSubmit,
  // onFocus,
  // multiple,
  containerStyle,
  // editContext,
  queryRef,
  // disabled = false,
  // disabledOptions = [],
}: TypesFieldComponentProps) => {
  const { t_i18n } = useFormatter();
  const { subTypes } = usePreloadedQuery(stixCyberObservablesLinesSubTypesQuery, queryRef);

  if (subTypes) {
    const subTypesEdges = subTypes.edges;
    const sortByLabel = sortBy(compose(toLower, prop('tlabel')));
    const translatedOrderedList = pipe(
      map((n) => n.node),
      map((n) => assoc('tlabel', t_i18n(`entity_${n.label}`), n)),
      sortByLabel,
    )(subTypesEdges);
    return (
      <Field
        component={SelectField}
        variant="standard"
        name={name}
        label={label}
        fullWidth={true}
        required={required}
        style={containerStyle}
      >
        {translatedOrderedList.map((subType) => (
          <MenuItem key={subType.id} value={subType.label}>
            {subType.tlabel}
          </MenuItem>
        ))}
      </Field>
    );
  }
};

type TypesFieldProps = Omit<TypesFieldComponentProps, 'queryRef'>;

const TypesField = (props: TypesFieldProps) => {
  const { name, label, containerStyle, required } = props;

  const queryRef = useQueryLoading(
    stixCyberObservablesLinesSubTypesQuery,
    { count: 25 },
  );
  const FallbackSelect = (
    <Field
      component={SelectField}
      variant="standard"
      name={name}
      label={label}
      fullWidth={true}
      required={required}
      style={containerStyle}
    />
  );

  return (
    <Suspense fallback={FallbackSelect}>
      {queryRef && (
        <TypesFieldComponent
          {...props}
          queryRef={queryRef}
        />
      )}
    </Suspense>
  );
};

export default TypesField;
