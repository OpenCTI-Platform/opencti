/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchQuery } from '../../../../relay/environment';

const RiskLifeCyclePhaseQuery = graphql`
  query RiskLifeCyclePhaseQuery {
    __type(name: "RiskLifeCyclePhase") {
      name
      description
      enumValues {
        name
        description
      }
    }
  }
`;

class RiskLifeCyclePhase extends Component {
  constructor(props) {
    super(props);
    this.state = {
      riskLifeCyclePhaseList: [],
    };
  }
  componentDidMount() {
    fetchQuery(RiskLifeCyclePhaseQuery)
      .toPromise()
      .then((data) => {
        const riskLifeCyclePhaseEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          }))
        )(data);
        this.setState({
          riskLifeCyclePhaseList: {
            ...this.state.entities,
            riskLifeCyclePhaseEntities,
          },
        });
      });
  }

  render() {
    const {
      t,
      name,
      size,
      label,
      style,
      variant,
      onChange,
      onFocus,
      containerstyle,
      editContext,
      disabled,
      helperText,
    } = this.props;
    const riskLifeCyclePhaseList = R.pathOr(
      [],
      ['riskLifeCyclePhaseEntities'],
      this.state.riskLifeCyclePhaseList
    );
    return (
      <div>
        <div className="clearfix" />
        <Field
          component={SelectField}
          name={name}
          label={label}
          fullWidth={true}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
          {riskLifeCyclePhaseList.map(
            (et, key) =>
              et.label && (
                <Tooltip title={et.label} value={et.value} key={et.label}>
                  <MenuItem value={et.value}>{et.value}</MenuItem>
                </Tooltip>
              )
          )}
        </Field>
      </div>
    );
  }
}
//RiskLifeCyclePhase
export default inject18n(RiskLifeCyclePhase);
