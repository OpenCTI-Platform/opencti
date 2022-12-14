/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro'
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchQuery } from '../../../../relay/environment';

const OperationalStatusFieldQuery = graphql`
 query OperationalStatusFieldQuery{
  __type(name: "OperationalStatus" ) {
    name enumValues {
      description
      name
    }
  }
}
`;

class OperationalStatusField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      operationalStatusList: [],
    }
  }
  componentDidMount() {
    fetchQuery(OperationalStatusFieldQuery)
      .toPromise()
      .then((data) => {
        const operationalStatusEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          })),
        )(data);
        this.setState({
          operationalStatusList: {
            ...this.state.entities,
            operationalStatusEntities
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
    const operationalStatusList = R.pathOr(
      [],
      ['operationalStatusEntities'],
      this.state.operationalStatusList,
    );
    return (
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
        <MenuItem value={''}>
          <em>None</em>
        </MenuItem>
        {operationalStatusList.map((operationalStatus, key) => (
          operationalStatus.label
          && <MenuItem key={key} value={operationalStatus.value}>
            {t(operationalStatus.label)}
          </MenuItem>
        ))}
      </Field>
    );
  }
}

export default inject18n(OperationalStatusField);
