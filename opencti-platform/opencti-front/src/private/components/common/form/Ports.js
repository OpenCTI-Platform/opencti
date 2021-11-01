import React, { Component, useState } from 'react';
import { createFragmentContainer, QueryRenderer as QR } from 'react-relay';
import { Field } from 'formik';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
import { SubscriptionFocus } from '../../../../components/Subscription';

class Ports extends Component {
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

    // const portsQuery = graphql`
    //   query PortsListQuery {
    //     documentaryAssetList {
    //       edges {
    //         node {
    //           ... on Server {
    //             ports {
    //               port_number,
    //               protocols
    //             }
    //           }
    //         }
    //       }
    //     }
    //   }
    // `;

    return (
      <div>
        {/* <QR
          environment={QueryRendererDarkLight}
          query={portsQuery}
          render={({ error, props }) => {
            console.log('these are the ports ', props);
            if (props && props.documentaryAssetList.edges) {
              return (
                <div>
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
                  props.documentaryAssetList.edges[1].node.ports.map((index) => (
                    <MenuItem key={index.port_number} value={index.port_number}>
                      {t(index.port_number)}
                    </MenuItem>
                  ))
                }
                </Field>
              </div>
              );
            }
            return <></>;
          }}
        /> */}
      </div>
    );
  }
}

export default inject18n(Ports);
