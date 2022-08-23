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

const ResponsiblePartiesQuery = graphql`
query ResponsiblePartiesQuery {
  poam {
    responsible_parties {
      edges {
        node {
          parties {
            name
            description
          }
          role {
            description
            name
          }
        }
      }
    }
  }
}
`;

class ResponsibleParties extends Component {
  constructor(props) {
    super(props);
    this.state = {
      ResponsiblePartiesList: [],
    };
  }
  componentDidMount() {
    fetchQuery(ResponsiblePartiesQuery)
      .toPromise()
      .then((data) => {
        const ResponsiblePartiesEntities = R.pipe(
          R.pathOr([], ['poam', 'responsible_parties', 'edges']),
          R.map((n) => ({
            label: n.node.description,
            value: n.node.name,
          }))
        )(data);
        this.setState({
          ResponsiblePartiesList: {
            ...this.state.entities,
            ResponsiblePartiesEntities,
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
    const ResponsiblePartiesList = R.pathOr(
      [],
      ['ResponsiblePartiesEntities'],
      this.state.ResponsiblePartiesList
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
          {ResponsiblePartiesList.map(
            (et, key) =>
              et.value && <MenuItem value={et.value}>{et.value}</MenuItem>
          )}
        </Field>
      </div>
    );
  }
}

export default inject18n(ResponsibleParties);
