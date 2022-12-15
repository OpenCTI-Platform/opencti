/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import Box from '@material-ui/core/Box';
import Chip from '@material-ui/core/Chip';
import Grid from '@material-ui/core/Grid';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchQuery } from '../../../../relay/environment';
import ItemIcon from '../../../../components/ItemIcon';

const installedHardwareAssetQuery = graphql`
  query InstalledAssetHardwareQuery {
    computingDeviceAssetList {
      edges {
        node {
          id
          name
          asset_type
        }
      }
    }
  }
`;

const installedSoftwareAssetQuery = graphql`
  query InstalledAssetSoftwareQuery(
    $filters: [SoftwareAssetFiltering]
  ){
    softwareAssetList(
      filters: $filters
    ) {
      edges {
        node {
          id
          name
          asset_type
          version
        }
      }
    }
  }
`;

class InstalledAsset extends Component {
  constructor(props) {
    super(props);
    this.state = {
      devices: [],
      softwareList: [],
    };
  }

  componentDidMount() {

    {
      this.props.type === 'hardware' && (
        fetchQuery(installedHardwareAssetQuery)
          .toPromise()
          .then((data) => {
            const installedHardwareEntities = R.pipe(
              R.pathOr([], ['computingDeviceAssetList', 'edges']),
              R.map((n) => ({
                id: n.node.id,
                name: n.node.name,
                type: n.node.asset_type,
              })),
            )(data);
            this.setState({
              devices: {
                ...this.state.entities,
                installedHardwareEntities
              },
            });
          })
      )
    }

    {
      this.props.type === 'software'
        && (
          fetchQuery(installedSoftwareAssetQuery, {
            filters: this.props.assetType ? [{ key: 'asset_type', values: [this.props.assetType] }] : [],
          })
            .toPromise()
            .then((data) => {
              const installedSoftwareEntities = R.pipe(
                R.pathOr([], ['softwareAssetList', 'edges']),
                R.map((n) => {
                  const softwareName = R.concat(n.node.name, " ");
                  const softwareNameWithVersion = R.concat(softwareName, n.node.version ? n.node.version : "");
                  return {
                    id: n.node.id,
                    name: n.node.name,
                    type: n.node.vendor_name,
                    version: n.node.version,
                    softwareNameWithVersion
                  }
                }),
              )(data);
              this.setState({
                softwareList: {
                  ...this.state.entities,
                  installedSoftwareEntities
                },
              });
            })
        )
    }
  }

  renderInstalledHardware() {
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
    const { selectedHardwareList } = this.state;
    const devices = R.pathOr(
      [],
      ['installedHardwareEntities'],
      this.state.devices,
    ); 

    const sort = R.sortWith(
      [
        R.ascend(R.prop('name'))
      ]
    );

    const sortedDeviceList = sort(devices);

    return (
      <div>
        <Field
          component={SelectField}
          name={name}
          label={label}
          multiple={multiple}
          fullWidth={true}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
          {sortedDeviceList.map((device) => (
            <MenuItem key={device.id} value={device.id}>
              {device.name && t(device.name)}
            </MenuItem>
          ))}
        </Field>
      </div>
    );
  }

  renderInstalledSoftware() {
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
    const softwareList = R.pathOr(
      [],
      ['installedSoftwareEntities'],
      this.state.softwareList,
    );

    const sortedSoftwareList = softwareList.sort(function(a, b) {
      return a.softwareNameWithVersion.localeCompare(b.softwareNameWithVersion, undefined, {
        numeric: true,
        sensitivity: 'base'
      });
    });
    return (
      <Field
        component={SelectField}
        name={name}
        label={label}
        multiple={multiple}
        fullWidth={true}
        containerstyle={containerstyle}
        variant={variant}
        disabled={disabled || false}
        size={size}
        style={style}
        helperText={helperText}
      >
        {!multiple && <MenuItem value={''}>
          <em>None</em>
        </MenuItem>}
        {sortedSoftwareList.map((software) => 
          {            
            return(
              software.softwareNameWithVersion
                && <MenuItem key={software.id} value={software.id}>
                  {t(software.softwareNameWithVersion)}
                </MenuItem>
            )
          }
        )}
      </Field>
    );
  }

  render() {
    if (this.props.type === 'hardware') {
      return this.renderInstalledHardware();
    }
    if (this.props.type === 'software') {
      return this.renderInstalledSoftware();
    }
    return <></>;
  }
}

export default inject18n(InstalledAsset);
