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
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';

const DependenciesQuery = graphql`
  query DependenciesQuery {
    oscalTasks {
      edges {
        node {
          name
          description
          task_type
        }
      }
    }
  }
`;

class Dependencies extends Component {
  constructor(props) {
    super(props);
    this.state = {
      DependenciesList: [],
    };
  }
  componentDidMount() {
    fetchDarklightQuery(DependenciesQuery)
      .toPromise()
      .then((data) => {
        const DependenciesEntities = R.pipe(
          R.pathOr([], ['oscalTasks', 'edges']),
          R.map((n) => ({
            label: n.node.description,
            value: n.node.name,
          }))
        )(data);
        this.setState({
          DependenciesList: {
            ...this.state.entities,
            DependenciesEntities,
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
    const DependenciesList = R.pathOr(
      [],
      ['DependenciesEntities'],
      this.state.DependenciesList
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
          {DependenciesList.map(
            (et, key) =>
              et.value && <MenuItem value={et.value}>{et.value}</MenuItem>
          )}
        </Field>
      </div>
    );
  }
}

export default inject18n(Dependencies);
