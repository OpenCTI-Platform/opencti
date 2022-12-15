/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro'
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchQuery } from '../../../../relay/environment';

const RiskStatusQuery = graphql`
 query RiskStatusQuery{
  __type(name: "RiskStatus" ) {
    name
    enumValues {
      name
      description
    }
  }
}
`;

class RiskStatus extends Component {
  constructor(props) {
    super(props);
    this.state = {
      riskStatusList: [],
    }
  }
  componentDidMount() {
    fetchQuery(RiskStatusQuery)
      .toPromise()
      .then((data) => {
        const riskStatusEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          })),
        )(data);
        this.setState({
          riskStatusList: {
            ...this.state.entities,
            riskStatusEntities
          },
        });
      })
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
    const riskStatusList = R.pathOr(
      [],
      ['riskStatusEntities'],
      this.state.riskStatusList,
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
          onChange={onChange}
          onFocus={onFocus}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
          MenuProps={{
            anchorOrigin: {
              vertical: 'bottom',
              horizontal: 'left',
            },
            getContentAnchorEl: null,
          }}
        >
          {riskStatusList.map((et, key) => (
            et.label
            && <Tooltip
              title={et.label}
              value={et.value}
              key={key}
            >
              <MenuItem value={et.value}>
                {et.value}
              </MenuItem>
            </Tooltip>
          ))}
        </Field>
      </div>
    );
  }
}
export default inject18n(RiskStatus);
