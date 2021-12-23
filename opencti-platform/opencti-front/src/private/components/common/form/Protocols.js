/* eslint-disable */
/* refactor */
import React, { Component, useState } from 'react';
import * as R from 'ramda';
import { Field } from 'formik';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';
import { SubscriptionFocus } from '../../../../components/Subscription';

const protocolsListQuery = graphql`
  query ProtocolsListQuery {
    __type(name: "NetworkAssetProtocol") { 
      name 
      enumValues { 
        name 
        description 
      } 
    }  
  }
`;

class Protocols extends Component {
  constructor(props) {
    super(props);
    this.state = {
      protocols: [],
    };
  }

  componentDidMount() {
    fetchDarklightQuery(protocolsListQuery)
      .toPromise()
      .then((data) => {
        const protocols = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            id: n.name,
            name: n.name,
          })),
        )(data);
        this.setState({
          protocols: {
            ...this.state.entities,
            protocols,
          },
        });
      });
  }

  render() {
    const {
      t,
      name,
      label,
      variant,
      onChange,
      onFocus,
      containerstyle,
      editContext,
      disabled,
    } = this.props;
    const protocolList = R.pathOr(
      [],
      ['protocols'],
      this.state.protocols,
    );
    return (
      // <div>
      <Field
        component={SelectField}
        variant='outlined'
        size='small'
        name={name}
        onFocus={onFocus}
        onChange={onChange}
        label={label}
        style={{ height: '38.09px' }}
        disabled={disabled}
        containerstyle={containerstyle}
      >
        {
          protocolList.map((protocol) => (
            <MenuItem key={protocol.id} value={protocol.name}>
              {t(protocol.name)}
            </MenuItem>
          ))
        }
      </Field>
      // </div>
    );
  }
}

export default inject18n(Protocols);
