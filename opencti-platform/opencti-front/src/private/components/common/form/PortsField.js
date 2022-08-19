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
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { Dialog, DialogContent, DialogActions, Button } from '@material-ui/core';
import NewTextField from '../../../../components/TextField';
import Delete from '@material-ui/icons/Delete';

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
  },
  inputTextField: {
    color: 'white',
  },
  textField: {
    background: theme.palette.header.background,
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '85px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
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
      open: false,
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
    this.setState({ ports: [...new Map(R.append(this.state.port, this.state.ports).map((item) => [item["port_number"], item])).values()]});
  }

  handleRemovePort(port_number, removeProtocol) {
    const portsAfterRemove = {
      port_number: port_number,
      protocols: R.find(R.propEq('port_number', port_number))(this.state.ports).protocols.filter(protocol => protocol !== removeProtocol),
    }
    this.setState(({ ports }) => ({ports: R.append(portsAfterRemove, ports.filter(port => port.port_number !== port_number))}), () => this.props.setFieldValue(this.props.name, this.state.ports));
  };

  handleSubmit() {
    console.log(this.state.ports)
    this.setState({ open: false}, () => this.props.setFieldValue(this.props.name, this.state.ports));
  }

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
      title,
      values,
    } = this.props;
    console.log(values);
    const protocolList = R.pathOr(
      [],
      ['protocols'],
      this.state.protocols,
    );

    return (
    <>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Typography>
          {t('Ports')}
        </Typography>
        <div style={{ float: 'left', margin: '5px 0 0 5px' }}>
          <Tooltip title={t('Ports')} >
            <Information fontSize="inherit" color="disabled" />
          </Tooltip>
        </div>
        <IconButton
          color="inherit"
          aria-label="Add"
          edge="end"      
          onClick={() => this.setState({ open: true })}
        >
          <AddIcon fontSize="small" style={{ marginTop: -2 }}/>
        </IconButton>
      </div>
      <Field
        component={NewTextField}
        name={name}
        fullWidth={true}
        disabled={true}
        multiline={true}
        rows="3"          
        className={classes.textField}
        InputProps={{
          className: classes.inputTextField,
        }}
        variant='outlined'            
      >
        {
          this.state.ports.map((port, key) => (
                  port.protocols && port.protocols.map((protocol) => (
                    <>
                      <div key={key} style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <Typography>
                          {`${t(port.port_number)} ${t(protocol)}`}
                        </Typography>                        
                      </div>                      
                    </>              
                  ))
          ))
        }
      </Field>      
      <Dialog 
        open={this.state.open}
        fullWidth={true}
        maxWidth='sm'
      >
        <DialogContent>
          {t(`Edit ${title}(es)`)}
        </DialogContent>
        <DialogContent>
        <div style={{ width:'100%',display:'flex', justifyContent: 'space-between'}}>
          <div style={{ width: '70%',display:'flex', placeItems:'center' }}>
            <Field
              component={TextField}
              // style={{ width: '20%' }}
              type="number"
              variant='outlined'
              value={this.state.port.port_number}
              onChange={this.handlePortChange.bind(this)}
              name="port_number"
              size='small'
              // fullWidth={true}
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
              label={'Protocol'}              
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
          </div>
          <div style={{ width:'30%', display:'flex', alignItems: 'flex-end' }}>
            <IconButton
              color="inherit"
              aria-label="Add"
              edge="end"
              disabled={!this.state.port.port_number || this.state.port.protocols.length === 0}
              onClick={this.handleAddPort.bind(this)}
            >
              <AddIcon fontSize="small" />
            </IconButton>
          </div>
        </div>
          
          
        </DialogContent>    
        <DialogContent>
          <div className={classes.scrollBg}>
            <div className={classes.scrollDiv}>
              <div className={classes.scrollObj}>
                {this.state.ports.map((port, key) => (
                  port.protocols && port.protocols.map((protocol) => (
                    <>
                      <div key={key} style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <Typography>
                          {`${port.port_number && t(port.port_number)} ${t(protocol)}`}
                        </Typography>
                        <IconButton onClick={this.handleRemovePort.bind(this, port.port_number, protocol)}>
                          <Delete />
                        </IconButton>
                      </div>
                      {/* <Chip
                        key={key}
                        disabled={disabled}
                        classes={{ root: classes.chip }}
                        label={`${port.port_number && t(port.port_number)} ${t(protocol)}`}
                        color="primary"
                        onDelete={this.handleRemovePort.bind(this, port.port_number, protocol)}
                        deleteIcon={<CancelIcon className={classes.deleteIcon}/>}
                      /> */}
                    </>              
                  ))
                ))}
              </div>
            </div>
          </div>         
        </DialogContent>        
        <DialogActions className={classes.dialogAction}>
          <Button
            variant='outlined'
            onClick={() => this.setState({ open: false })}
          >
            {t('Cancel')}
          </Button>
          <Button              
            variant='contained'
            onClick={this.handleSubmit.bind(this)}
            color="primary"
          >
            {t('Submit')}
          </Button>
        </DialogActions>
      </Dialog>      
    </>
    );
  }
}

// export default inject18n(PortsField);
export default R.compose(
  inject18n,
  withStyles(styles),
)(PortsField);
