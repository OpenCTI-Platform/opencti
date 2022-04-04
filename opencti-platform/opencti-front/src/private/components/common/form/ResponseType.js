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
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';

const ResponseTypeQuery = graphql`
  query ResponseTypeQuery {
    __type(name: "ResponseType") {
      name
      description
      enumValues {
        name
        description
      }
    }
  }
`;

class ResponseType extends Component {
  constructor(props) {
    super(props);
    this.state = {
      responseTypeList: [],
    };
  }
  componentDidMount() {
    fetchDarklightQuery(ResponseTypeQuery)
      .toPromise()
      .then((data) => {
        const responseTypeEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          }))
        )(data);
        this.setState({
          responseTypeList: {
            ...this.state.entities,
            responseTypeEntities,
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
    const responseTypeList = R.pathOr(
      [],
      ['responseTypeEntities'],
      this.state.responseTypeList
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
          {responseTypeList.map(
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

export default inject18n(ResponseType);
