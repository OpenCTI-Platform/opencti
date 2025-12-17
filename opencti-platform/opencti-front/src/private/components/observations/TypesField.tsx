import React, { Suspense } from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../components/i18n';
import SelectField from '../../../components/fields/SelectField';
import { stixCyberObservablesLinesSubTypesQuery } from './stix_cyber_observables/StixCyberObservablesLines';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { StixCyberObservablesLinesSubTypesQuery } from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservablesLinesSubTypesQuery.graphql';

interface TypesFieldComponentProps {
  queryRef: PreloadedQuery<StixCyberObservablesLinesSubTypesQuery>;
  name: string;
  label?: string;
  required?: boolean;
  containerstyle?: Record<string, string | number>;
  multiple?: boolean;
  onChange?: (name: string, value: string | string[]) => void;
}
interface Tlabel {
  tlabel: string;
}

const TypesFieldComponent = ({
  name,
  label,
  required = false,
  containerstyle,
  queryRef,
}: TypesFieldComponentProps) => {
  const { t_i18n } = useFormatter();
  const { subTypes } = usePreloadedQuery(stixCyberObservablesLinesSubTypesQuery, queryRef);

  if (subTypes) {
    const subTypesEdges = subTypes.edges;
    const sortByLabel = <T extends Tlabel>(arr: T[]): T[] =>
      [...arr].sort((a, b) => {
        const labelA = String(a.tlabel).toLowerCase();
        const labelB = String(b.tlabel).toLowerCase();
        return labelA.localeCompare(labelB);
      });

    const translatedOrderedList = sortByLabel(
      subTypesEdges
        .map((n) => n.node)
        .map((n) => ({
          ...n,
          tlabel: t_i18n(`entity_${n.label}`),
        })),
    );
    return (
      <Field
        component={SelectField}
        variant="standard"
        name={name}
        label={label}
        fullWidth={true}
        required={required}
        containerstyle={containerstyle}
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
  const { name, label, containerstyle, required } = props;

  const queryRef = useQueryLoading<StixCyberObservablesLinesSubTypesQuery>(
    stixCyberObservablesLinesSubTypesQuery,
    { type: 'Stix-Cyber-Observable' },
  );
  const FallbackSelect = (
    <Field
      component={SelectField}
      variant="standard"
      fullWidth
      name={name}
      label={label}
      required={required}
      containerstyle={containerstyle}
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
