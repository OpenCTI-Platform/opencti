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
import { fetchQuery } from '../../../../relay/environment';

const dataUsageRestrictionFieldQuery = graphql`
  query DataUsageRestrictionFieldQuery {
    dataMarkings {
      edges {
        node {
          ... on IEPMarking {
            id
            name
          }
          ... on TLPMarking {
            id
            name
          }
          ... on StatementMarking {
            id
            name
          }
        }
      }
    }
  }
`;

class DataUsageRestrictionField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      list: [],
    }
  }
  componentDidMount() {
    fetchQuery(dataUsageRestrictionFieldQuery)
      .toPromise()
      .then((data) => {
        const dataMarkings = R.pipe(
          R.pathOr([], ['dataMarkings', 'edges']),
          R.map((n) => ({
            id: n.node.id,
            name: n.node.name,
          })),
        )(data);
        this.setState({
          list: [
            ...this.state.list,
            dataMarkings
          ],
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
    console.log(this.state.list)
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
          {/* {RolesFieldList.map((resp, key) => (
            resp.id
            && <MenuItem value={resp.id}>
              {resp.name}
            </MenuItem>
          ))} */}
        </Field>
      </div>
    );
  }
}

export default inject18n(DataUsageRestrictionField);
