import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchQuery } from '../../../../relay/environment';

const securityCategorizationFieldCategorizationQuery = graphql`
query SecurityCategorizationFieldCategorizationQuery {
  informationTypeCatalogs {
    edges {
      node {
        id
        title
        description
      }
    }
  }
}
`;

class SecurityCategorizationField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      categorizationSystemField: [],
    };
  }

  componentDidMount() {
    fetchQuery(securityCategorizationFieldCategorizationQuery)
      .toPromise()
      .then((data) => {
        const SecurityCategorizationEntities = R.pipe(
          R.pathOr([], ['informationTypeCatalogs', 'edges']),
          R.map((n) => ({
            id: n.node.id,
            label: n.node.description,
            value: n.node.title,
          })),
        )(data);
        this.setState({
          categorizationSystemField: {
            ...this.state.entities,
            SecurityCategorizationEntities,
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
      onFocus,
      variant,
      required,
      onChange,
      disabled,
      editContext,
      categoryField,
      containerstyle,
      informationTypeField,
    } = this.props;
    const categorizationSystemField = R.pathOr(
      [],
      ['SecurityCategorizationEntities'],
      this.state.categorizationSystemField,
    );
    return (
      <>
        <div className='clearfix' />
        <Field
          component={SelectField}
          name={name}
          label={label}
          fullWidth={true}
          onChange={onChange}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
        >
          {!required && <MenuItem value={''}>
            <em>None</em>
          </MenuItem>}
          {name === 'catalog' && categorizationSystemField.map(
            (categorization, key) => categorization.id && (
              <MenuItem key={key} value={categorization.id}>
                {categorization.value && t(categorization.value)}
              </MenuItem>
            ),
          )}
          {name === 'system' && categoryField.map(
            (category, key) => category && (
              <MenuItem key={key} value={category}>
                {category && t(category)}
              </MenuItem>
            ),
          )}
          {name === 'information_type' && informationTypeField.map(
            (informationType, key) => informationType.id && (
              <MenuItem key={key} value={informationType.id}>
                {informationType.title && t(informationType.title)}
              </MenuItem>
            ),
          )}
        </Field>
      </>
    );
  }
}

export default inject18n(SecurityCategorizationField);
