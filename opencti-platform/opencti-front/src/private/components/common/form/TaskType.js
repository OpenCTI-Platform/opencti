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

const TaskTypeQuery = graphql`
  query TaskTypeQuery(
    $type: String!
  ) {
    __type(name: $type) {
      name
      description
      enumValues {
        name
        description
      }
    }
  }
`;

class TaskType extends Component {
  constructor(props) {
    super(props);
    this.state = {
      TaskTypeList: []
    };
  }

  componentDidMount() {
    fetchQuery(TaskTypeQuery, {
      type: this.props.taskType,
    })
      .toPromise()
      .then((data) => {
        const TaskTypeEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          }))
        )(data);
        this.setState({
          TaskTypeList: {
            ...this.state.entities,
            TaskTypeEntities,
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
      required,
    } = this.props;
    const TaskTypeList = R.pathOr(
      [],
      ['TaskTypeEntities'],
      this.state.TaskTypeList
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
        {!required && <MenuItem value={''}>
            <em>None</em>
          </MenuItem>}          
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

export default inject18n(TaskType);
