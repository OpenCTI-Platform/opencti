/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import { Information } from 'mdi-material-ui';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchQuery } from '../../../../relay/environment';

const OscalMediaTypeListQuery = graphql`
  query OscalMediaTypeListQuery {
    __type(name: "OscalMediaType") {
      name
      description
      enumValues {
        name
        description
      }
    }
  }
`;

class OscalMediaTypeList extends Component {
  constructor(props) {
    super(props);
    this.state = {
      OscalMediaTypeList: []
    };
  }

  componentDidMount() {
    fetchQuery(OscalMediaTypeListQuery)
      .toPromise()
      .then((data) => {
        const OscalMediaTypeEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          }))
        )(data);
        this.setState({
          OscalMediaTypeList: {
            ...this.state.entities,
            OscalMediaTypeEntities,
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
    const TaskTypeList = R.pathOr(
      [],
      ['OscalMediaTypeEntities'],
      this.state.OscalMediaTypeList
    );
    return (
      <div>
        <div className='clearfix' />
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
          {TaskTypeList.map(
            (et, key) =>
              et.value && (
                <MenuItem key={key} value={et.value}>{et.value}</MenuItem>
              )
          )}
        </Field>
      </div>
    );
  }
}

export default inject18n(OscalMediaTypeList);
