import { CSSProperties, ReactNode, useState } from 'react';
import { union } from 'ramda';
import { Field } from 'formik';
import { fetchQuery } from '../../../../relay/environment';
import { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../../components/ComboboxField';
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

  const searchKillChainPhases = (search: string) => {
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
  };

  return (
    <Field
      component={ComboboxField}
      name={name}
      style={style}
      required={required}
      multiple={true}
      disabled={disabled}
      label={t_i18n('Kill chain phases')}
      helperText={helpertext}
      noOptionsText={t_i18n('No available options')}
      options={killChainPhases}
      // No getChipColor here on purpose: this query maps label, value, kill_chain_name and
      // phase_name and never a colour, so `option.color` is always undefined.
      onInputChange={(search: string, meta: ComboboxChangeMeta) => {
        if (meta.cause === 'type') searchKillChainPhases(search);
      }}
      onFocusInput={() => searchKillChainPhases('')}
      onChange={typeof onChange === 'function' ? onChange : undefined}
      renderOption={(option: KillChainPhaseFieldOption) => (
        <>
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
        </>
      )}
    />
  );
};

export default KillChainPhasesField;
