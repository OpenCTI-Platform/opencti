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

const AssociatedActivitiesQuery = graphql`
query AssociatedActivitiesQuery {
  activities {
    edges {
      node {
        __typename
        id
        entity_type
        created
        modified
        name
        description
        methods
      }
    }
  }
}
`;

class AssociatedActivities extends Component {
  constructor(props) {
    super(props);
    this.state = {
      AssociatedActivitiesList: [],
    };
  }
  componentDidMount() {
    fetchQuery(AssociatedActivitiesQuery)
      .toPromise()
      .then((data) => {
        const AssociatedActivitiesEntities = R.pipe(
          R.pathOr([], ['activities', 'node']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          }))
        )(data);
        this.setState({
          AssociatedActivitiesList: {
            ...this.state.entities,
            AssociatedActivitiesEntities,
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
    const AssociatedActivitiesList = R.pathOr(
      [],
      ['AssociatedActivitiesEntities'],
      this.state.AssociatedActivitiesList
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
          {AssociatedActivitiesList.map(
            (et, key) =>
              et.value && (
                <MenuItem value={et.value}>{et.value}</MenuItem>
              )
          )}
        </Field>
      </div>
    );
  }
}

export default inject18n(AssociatedActivities);
