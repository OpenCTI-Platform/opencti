/* eslint-disable */
/* refactor */
import React, { Component, useState } from 'react';
import * as R from 'ramda';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import Typography from '@material-ui/core/Typography';
import CancelIcon from '@material-ui/icons/Cancel'
import IconButton from '@material-ui/core/IconButton';
import Chip from '@material-ui/core/Chip';
import AddIcon from '@material-ui/icons/Add';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import { fetchQuery } from '../../../../relay/environment';
import { SubscriptionFocus } from '../../../../components/Subscription';

const styles = (theme) => ({
  chip: {
    margin: '0 7px 7px 0',
    color: theme.palette.header.text,
    backgroundColor: theme.palette.header.background,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
  deleteIcon: {
    color: theme.palette.header.text,
  }
});

const protocolsListQuery = graphql`
  query PortsFieldQuery {
    __type(name: "NetworkAssetProtocol") { 
      name 
      enumValues { 
        name 
        description 
      } 
    }  
  }
`;

class PortsField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      protocols: [],
      ports: this.props.values.ports.length > 0 ? this.props.values.ports : [],
      port: {
        port_number: '',
        protocols: [],
      },
    };
  }

  componentDidMount() {
    fetchQuery(protocolsListQuery)
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
            ...this.state.port.protocols,
            protocols,
          },
        });
      });
  }

  handlePortChange(name, value) {
    if (name === 'port_number') {
      this.setState({
        port: {
          ...this.state.port,
          port_number: value ? parseInt(value) : '',
        },
      })
    }
    if (name === 'protocols') {
      this.setState({
        port: {
          ...this.state.port,
          protocols: value ? value : [],
        },
      })
    }
  }

  handleAddPort() {
    this.setState({ ports: [...new Map(R.append(this.state.port, this.state.ports).map((item) => [item["port_number"], item])).values()]}, () => this.props.setFieldValue(this.props.name, this.state.ports));
  }

  handleRemovePort(port_number, removeProtocol) {
    const portsAfterRemove = {
      port_number: port_number,
      protocols: R.find(R.propEq('port_number', port_number))(this.state.ports).protocols.filter(protocol => protocol !== removeProtocol),
    }
    this.setState(({ ports }) => ({ports: R.append(portsAfterRemove, ports.filter(port => port.port_number !== port_number))}), () => this.props.setFieldValue(this.props.name, this.state.ports));
  };

  render() {
    const {
      t,
      name,
      label,
      classes,
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
      <div>
        <Typography
          variant="h3"
          color="textSecondary"
          gutterBottom={true}
          style={{ float: 'left', marginTop: 20 }}
        >
          {t('Ports')}
        </Typography>
        <div style={{ float: 'left', margin: '8px 0 0 5px' }}>
          <Tooltip title={t('Ports')} >
            <Information fontSize="inherit" color="disabled" />
          </Tooltip>
          <IconButton
            color="inherit"
            aria-label="Add"
            edge="end"
            disabled={!this.state.port.port_number || this.state.port.protocols.length === 0}
            onClick={this.handleAddPort.bind(this)}
          >
            <AddIcon fontSize="small" style={{ marginTop: -2 }} />
          </IconButton>
        </div>
        <div style={{ marginTop: 2 }} className="clearfix" />
        <Field
          component={TextField}
          style={{ width: '50%' }}
          type="number"
          variant='outlined'
          value={this.state.port.port_number}
          onChange={this.handlePortChange.bind(this)}
          name="port_number"
          size='small'
          fullWidth={true}
          label={'Number'}
        />
        <Field
          component={SelectField}
          variant='outlined'
          size='small'
          multiple={true}
          name='protocols'
          value={this.state.port.protocols}
          onFocus={onFocus}
          onChange={this.handlePortChange.bind(this)}
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
        <div style={{ marginTop: 10 }} className="clearfix" />
        {this.state.ports.map((port, key) => (
          port.protocols && port.protocols.map((protocol) => (
            <Chip
              key={key}
              disabled={disabled}
              classes={{ root: classes.chip }}
              label={`${port.port_number && t(port.port_number)} ${t(protocol)}`}
              color="primary"
              onDelete={this.handleRemovePort.bind(this, port.port_number, protocol)}
              deleteIcon={<CancelIcon className={classes.deleteIcon}/>}
            />
          ))
        ))}
      </div>
    );
  }
}

// export default inject18n(PortsField);
export default R.compose(
  inject18n,
  withStyles(styles),
)(PortsField);
