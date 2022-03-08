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

const EntryTypeQuery = graphql`
 query EntryTypeQuery{
  __type(name: "EntryType" ) {
    name
    enumValues {
      name
      description
    }
  }
}
`;

class EntryType extends Component {
  constructor(props) {
    super(props);
    this.state = {
      entryTypeList: [],
    }
  }
  componentDidMount() {
    fetchDarklightQuery(EntryTypeQuery)
      .toPromise()
      .then((data) => {
        const entryTypeEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          })),
        )(data);
        this.setState({
          entryTypeList: {
            ...this.state.entities,
            entryTypeEntities
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
      containerstyle,
      editContext,
      disabled,
      helperText,
    } = this.props;
    const entryTypeList = R.pathOr(
      [],
      ['entryTypeEntities'],
      this.state.entryTypeList,
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
          {entryTypeList.map((et, key) => (
            et.label
            && <Tooltip
              title={et.label}
              value={et.value}
              key={et.label}
            >
              <MenuItem value={et.value}>
                {et.value}
              </MenuItem>
            </Tooltip>
          ))}
        </Field>
      </div>
    );
  }
}
//EntryType
export default inject18n(EntryType);
