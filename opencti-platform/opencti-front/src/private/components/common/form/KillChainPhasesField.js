import React, { Component } from 'react';
import {
  compose,
  pathOr,
  pipe,
  map,
  sortWith,
  ascend,
  path,
  union,
} from 'ramda';
import { Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { Launch } from 'mdi-material-ui';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import { killChainPhasesSearchQuery } from '../../settings/KillChainPhases';

const styles = () => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
});

class KillChainPhasesField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      killChainPhases: [],
    };
  }

  searchKillChainPhases(event) {
    fetchQuery(killChainPhasesSearchQuery, {
      search: event && event.target.value,
    })
      .toPromise()
      .then((data) => {
        const killChainPhases = pipe(
          pathOr([], ['killChainPhases', 'edges']),
          sortWith([ascend(path(['node', 'x_opencti_order']))]),
          map((n) => ({
            label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
            value: n.node.id,
          })),
        )(data);
        this.setState({
          killChainPhases: union(this.state.killChainPhases, killChainPhases),
        });
      });
  }

  render() {
    const { t, name, style, classes, onChange, helpertext } = this.props;
    return (
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        multiple={true}
        textfieldprops={{
          variant: 'standard',
          label: t('Kill chain phases'),
          helperText: helpertext,
          onFocus: this.searchKillChainPhases.bind(this),
        }}
        noOptionsText={t('No available options')}
        options={this.state.killChainPhases}
        onInputChange={this.searchKillChainPhases.bind(this)}
        onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
        renderOption={(props, option) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <Launch />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
      />
    );
  }
}

export default compose(inject18n, withStyles(styles))(KillChainPhasesField);
