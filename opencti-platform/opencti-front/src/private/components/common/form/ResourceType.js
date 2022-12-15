/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchQuery } from '../../../../relay/environment';

const ResourceTypeQuery = graphql`
  query ResourceTypeQuery {
    __type(name: "RiskAssertionState") {
      name
      description
      enumValues {
        name
        description
      }
    }
  }
`;

class ResourceType extends Component {
  constructor(props) {
    super(props);
    this.state = {
      ResourceTypeList: [],
    };
  }
  componentDidMount() {
    fetchQuery(ResourceTypeQuery)
      .toPromise()
      .then((data) => {
        const ResourceTypeEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          }))
        )(data);
        this.setState({
          ResourceTypeList: {
            ...this.state.entities,
            ResourceTypeEntities,
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
    const ResourceTypeList = R.pathOr(
      [],
      ['ResourceTypeEntities'],
      this.state.ResourceTypeList
    );
    return (
      <div>
        <div className='clearfix' />
        <Field
          component={SelectField}
          name={name}
          onChange={onChange}
          onFocus={onFocus}
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
          {ResourceTypeList.map(
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

export default inject18n(ResourceType);
