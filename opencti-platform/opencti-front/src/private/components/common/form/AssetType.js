/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import ItemIcon from '../../../../components/ItemIcon';
import { fetchQuery } from '../../../../relay/environment';

const assetTypeQuery = graphql`
 query AssetTypeQuery(
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

class AssetType extends Component {
  constructor(props) {
    super(props);
    this.state = {
      assetTypes: {},
    }
  }
  componentDidMount() {
    fetchQuery(assetTypeQuery, {
      type: `${this.props.assetType}AssetType`,
    })
      .toPromise()
      .then((data) => {
        const assetTypeEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
            type: n.name,
          })),
        )(data);
        this.setState({
          assetTypes: {
            ...this.state.entities,
            assetTypeEntities
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
    const assetTypes = R.pathOr(
      [],
      ['assetTypeEntities'],
      this.state.assetTypes,
    );
    return (
      <Field
        component={SelectField}
        name={name}
        label={label}
        displayEmpty
        onChange={onChange}
        onFocus={onFocus}
        fullWidth={true}
        containerstyle={containerstyle}
        variant={variant}
        disabled={disabled || false}
        size={size}
        style={style}
        helperText={helperText}
      >
        {assetTypes.map((assetType, key) => (
          assetType.label
          && <MenuItem key={key} value={assetType.value}>
            <ItemIcon variant="inline" type={assetType.value} /> {t(assetType.label)}
          </MenuItem>
        ))}
      </Field>
    );
  }
}

export default inject18n(AssetType);
