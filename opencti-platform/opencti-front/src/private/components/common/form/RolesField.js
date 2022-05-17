/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import graphql from 'babel-plugin-relay/macro'
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';

const RolesFieldQuery = graphql`
query RolesFieldQuery{
  oscalRoles {
      edges {
        node {
          id
          name
          role_identifier
        }
      }
    }
  }
`;

class RolesField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      RolesFieldList: [],
    }
  }
  componentDidMount() {
    fetchDarklightQuery(RolesFieldQuery)
      .toPromise()
      .then((data) => {
        const RolesFieldEntities = R.pipe(
          R.pathOr([], ['oscalRoles', 'edges']),
          R.map((n) => ({
            id: n.node.id,
            role: n.node.role_identifier,
            name: n.node.name,
          })),
        )(data);
        this.setState({
          RolesFieldList: {
            ...this.state.entities,
            RolesFieldEntities
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
      multiple,
      containerstyle,
      editContext,
      disabled,
      helperText,
    } = this.props;
    const RolesFieldList = R.pathOr(
      [],
      ['RolesFieldEntities'],
      this.state.RolesFieldList,
    );
    return (
      <div>
        <div className="clearfix" />
        <Field
          component={SelectField}
          name={name}
          label={label}
          fullWidth={true}
          multiple={multiple}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
          {RolesFieldList.map((resp, key) => (
            resp.id
            && <MenuItem value={resp.id}>
              {resp.name}
            </MenuItem>
          ))}
        </Field>
      </div>
    );
  }
}

export default inject18n(RolesField);
