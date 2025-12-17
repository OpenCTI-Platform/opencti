import { useState } from 'react';
import { pathOr, pipe, map, sortWith, ascend, path, union } from 'ramda';
import { Field } from 'formik';
import { makeStyles } from '@mui/styles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { killChainPhasesSearchQuery } from '../../settings/KillChainPhases';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';

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

const KillChainPhasesField = ({
  style,
  name,
  onChange,
  helpertext,
  disabled,
  required = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [killChainPhases, setKillChainPhases] = useState([]);

  const searchKillChainPhases = (event) => {
    fetchQuery(killChainPhasesSearchQuery, {
      search: event && event.target.value,
    })
      .toPromise()
      .then((data) => {
        const kcp = pipe(
          pathOr([], ['killChainPhases', 'edges']),
          sortWith([ascend(path(['node', 'x_opencti_order']))]),
          map((n) => ({
            label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
            value: n.node.id,
            kill_chain_name: n.node.kill_chain_name,
            phase_name: n.node.phase_name,
          })),
        )(data);
        setKillChainPhases(union(killChainPhases, kcp));
      });
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
      renderOption={(props, option) => (
        <li {...props} key={option.value}>
          <div className={classes.icon} style={{ color: option.color }}>
            <ItemIcon type="Kill-Chain-Phase" />
          </div>
          <div className={classes.text}>{option.label}</div>
        </li>
      )}
    />
  );
};

export default KillChainPhasesField;
