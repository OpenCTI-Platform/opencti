import { CSSProperties, HTMLAttributes, ReactNode, SyntheticEvent, useState } from 'react';
import { union } from 'ramda';
import { Field } from 'formik';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { killChainPhasesSearchQuery } from '../../settings/KillChainPhases';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption } from '../../../../utils/field';
import { KillChainPhasesSearchQuery$data } from '../../settings/__generated__/KillChainPhasesSearchQuery.graphql';
import { getNodes } from '../../../../utils/connection';

interface KillChainPhaseFieldOption extends FieldOption {
  kill_chain_name: string;
  phase_name: string;
}

interface KillChainPhasesFieldProps {
  name: string;
  onChange?: (name: string, value: KillChainPhaseFieldOption[]) => void;
  style?: CSSProperties;
  helpertext?: ReactNode;
  disabled?: boolean;
  required?: boolean;
}

const KillChainPhasesField = ({
  style,
  name,
  onChange,
  helpertext,
  disabled,
  required = false,
}: KillChainPhasesFieldProps) => {
  const { t_i18n } = useFormatter();
  const [killChainPhases, setKillChainPhases] = useState<KillChainPhaseFieldOption[]>([]);

  const searchKillChainPhases = (event?: SyntheticEvent<Element, Event>) => {
    if (event?.target instanceof HTMLInputElement) {
      const search = event.target.value ?? '';
      fetchQuery(killChainPhasesSearchQuery, { search })
        .toPromise()
        .then((data) => {
          const dataNodes = getNodes((data as KillChainPhasesSearchQuery$data).killChainPhases);
          dataNodes.sort((a, b) => (a.x_opencti_order ?? 0) - (b.x_opencti_order ?? 0));
          const kcp = dataNodes.map((node) => {
            return {
              label: `[${node.kill_chain_name}] ${node.phase_name}`,
              value: node.id,
              kill_chain_name: node.kill_chain_name,
              phase_name: node.phase_name,
            };
          });
          setKillChainPhases(union(killChainPhases, kcp));
        });
    }
  };

  return (
    <Field
      component={AutocompleteField}
      name={name}
      style={style}
      required={required}
      multiple={true}
      disabled={disabled}
      textfieldprops={{
        variant: 'standard',
        label: t_i18n('Kill chain phases'),
        helperText: helpertext,
        onFocus: searchKillChainPhases,
        required,
      }}
      noOptionsText={t_i18n('No available options')}
      options={killChainPhases}
      onInputChange={searchKillChainPhases}
      onChange={typeof onChange === 'function' ? onChange : null}
      renderOption={(
        props: HTMLAttributes<HTMLLIElement>,
        option: KillChainPhaseFieldOption,
      ) => (
        <li {...props} key={option.value}>
          <div
            style={{
              paddingTop: 4,
              display: 'inline-block',
              color: option.color,
            }}
          >
            <ItemIcon type="Kill-Chain-Phase" />
          </div>
          <div
            style={{
              display: 'inline-block',
              flexGrow: 1,
              marginLeft: 10,
            }}
          >{option.label}
          </div>
        </li>
      )}
    />
  );
};

export default KillChainPhasesField;
