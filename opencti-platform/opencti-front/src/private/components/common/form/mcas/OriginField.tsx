import { Field } from 'formik';
import { useEffect, useState } from 'react';
import { useFormatter } from '../../../../../components/i18n';
import AutocompleteField from '../../../../../components/AutocompleteField';
import Origin, { OriginsType } from './OriginEnum';
import { EditOperation } from '../../../threats/threat_actors_individual/__generated__/ThreatActorIndividualEditionDetailsFieldPatchMutation.graphql';

interface OriginFieldComponentProps {
  name: string,
  label: string,
  initialValue: string | null,
  style: {
    marginTop?: number;
    width?: string;
  },
  handleChange: (
    name: string,
    value: string | string[] | null,
    operation: EditOperation,
  ) => void,
}

const OriginFieldComponent = ({
  name,
  label,
  initialValue,
  style,
  handleChange,
}: OriginFieldComponentProps) => {
  const { t } = useFormatter();
  const [originOptions, setOriginOptions] = useState<OriginsType>({});
  const [originKeys, setOriginKeys] = useState<OriginsType>({});

  useEffect(() => {
    const keyToValue: OriginsType = {};
    const valueToKey: OriginsType = {};
    Object.entries(Origin).forEach(([k, v]) => {
      keyToValue[k] = v;
      valueToKey[v] = k;
    });
    setOriginOptions(keyToValue);
    setOriginKeys(valueToKey);
  }, []);

  return (
    <Field
      component={AutocompleteField}
      name={name}
      textfieldprops={{
        variant: 'standard',
        label: t(label),
      }}
      value={initialValue ? t(originOptions?.[initialValue] ?? initialValue) : null}
      style={style}
      noOptionsText={t('No available options')}
      options={Object.values(originOptions || {})}
      renderOption={(props: object, option: string | null) => <li {...props}>
          {t(option)}
        </li>
      }
      onChange={(_: Event, v: string | null) => {
        if (!!v && originKeys?.[v]) {
          handleChange(name, originKeys?.[v], 'replace');
        } else {
          handleChange(name, null, 'remove');
        }
      }}
    />
  );
};

export default OriginFieldComponent;
