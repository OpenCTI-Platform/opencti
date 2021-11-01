import React, { Component, useState } from 'react';
import { createFragmentContainer, QueryRenderer as QR } from 'react-relay';
import { Field } from 'formik';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
import { SubscriptionFocus } from '../../../../components/Subscription';

class AssetTaglist extends Component {
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

    const assetTagQuery = graphql`
      query AssetTaglistQuery {
        itAssetList {
          edges {
            node {
              asset_tag
            }
          }
        }
      }
    `;

    return (
      <div>
        <QR
          environment={QueryRendererDarkLight}
          query={assetTagQuery}
          render={({ error, props }) => {
            console.log('AssetTagListpropr', props);
            if (props && props.itAssetList.edges) {
              return (
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
                  props.itAssetList.edges.map((index) => (
                    index
                    && <MenuItem key={index.node.asset_tag} value={index.node.asset_tag}>
                      {index && t(index.node.asset_tag)}
                    </MenuItem>
                  ))
                }
                </Field>
              );
            }
            return <></>;
          }}
        />
      </div>
    );
  }
}

export default inject18n(AssetTaglist);
