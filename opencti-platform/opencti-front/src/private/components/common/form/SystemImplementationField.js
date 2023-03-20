/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro';
import LinkIcon from '@material-ui/icons/Link';
import LinkOff from '@material-ui/icons/LinkOff';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import {
  Dialog, DialogContent, DialogActions, Select, MenuItem, InputLabel, FormControl,
} from '@material-ui/core';
import inject18n from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import HyperLinks from '../../../../components/HyperLinks';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
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
  inputTextField: {
    color: 'white',
  },
  dialogAction: {
    margin: '15px 20px 15px 0',
  },
  link: {
    textAlign: 'left',
    fontSize: '1rem',
    display: 'flex',
    minWidth: '50px',
    width: '100%',
  },
  launchIcon: {
    marginRight: '5%',
  },
  linkTitle: {
    color: '#fff',
    minWidth: 'fit-content',
  },
});

const systemImplementationFieldInventoryItemQuery = graphql`
  query SystemImplementationFieldInventoryItemQuery(
    $orderedBy: InventoryItemsOrdering,
    $orderMode: OrderingMode
  ){
    inventoryItemList(
      orderedBy: $orderedBy,
      orderMode: $orderMode
    ) {
      pageInfo {
        globalCount
        hasNextPage
      }
      edges {
        node {
          id
          asset_type
          name
        }
      }
    }
  }
`;

const systemImplementationFieldComponentListQuery = graphql`
  query SystemImplementationFieldComponentListQuery(
    $orderedBy: ComponentsOrdering,
    $orderMode: OrderingMode
  ){
    componentList(
      orderedBy: $orderedBy,
      orderMode: $orderMode
    ) {
      pageInfo {
        globalCount
        hasNextPage
      }
      edges {
        node {
          id
          component_type
          name
        }
      }
    }
  }
`;

const systemImplementationFieldOscalUsersQuery = graphql`
  query SystemImplementationFieldOscalUsersQuery(
    $orderedBy: OscalUsersOrdering,
    $orderMode: OrderingMode
  ){
    oscalUsers(
      orderedBy: $orderedBy,
      orderMode: $orderMode
    ) {
      pageInfo {
        globalCount
        hasNextPage
      }
      edges {
        node {
          id
          user_type
          name
        }
      }
    }
  }
`;

const systemImplementationFieldLeveragedAuthorizationsQuery = graphql`
  query SystemImplementationFieldleveragedAuthorizationsQuery(
    $orderedBy: OscalLeveragedAuthorizationOrdering,
    $orderMode: OrderingMode
  ){
    leveragedAuthorizations(
      orderedBy: $orderedBy,
      orderMode: $orderMode
    ) {
      pageInfo {
        globalCount
        hasNextPage
      }
      edges {
        node {
          id
          title
        }
      }
    }
  }
`;

class SystemImplementationField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      value: '',
      error: false,
      isSubmitting: true,
      data: this.props.data ? [...this.props.data] : [],
      list: [],
    };
  }

  handleSearchEntities() {
    // eslint-disable-next-line no-case-declarations
    let nameQuery = '';
    // eslint-disable-next-line no-case-declarations
    let namePath = [];
    // eslint-disable-next-line no-case-declarations
    let nameArguments = { orderedBy: '', orderMode: '' };

    if (this.props.name === 'inventory_item') {
      nameQuery = systemImplementationFieldInventoryItemQuery;
      namePath = ['inventoryItemList', 'edges'];
      nameArguments.orderedBy = 'name';
      nameArguments.orderMode = 'asc';
    }
    if (this.props.name === 'component') {
      nameQuery = systemImplementationFieldComponentListQuery;
      namePath = ['componentList', 'edges'];
      nameArguments.orderedBy = 'name';
      nameArguments.orderMode = 'asc';
    }
    if (this.props.name === 'leveraged_authorization') {
      nameQuery = systemImplementationFieldLeveragedAuthorizationsQuery;
      namePath = ['leveragedAuthorizations', 'edges'];
      nameArguments.orderedBy = 'name';
      nameArguments.orderMode = 'desc';
    }
    if (this.props.name === 'user_type') {
      nameQuery = systemImplementationFieldOscalUsersQuery;
      namePath = ['oscalUsers', 'edges'];
      nameArguments.orderedBy = 'name';
      nameArguments.orderMode = 'asc';
    }
    fetchQuery(nameQuery, {
      orderedBy: nameArguments.orderedBy,
      orderMode: nameArguments.orderMode,
    })
      .toPromise()
      .then((data) => {
        const installedHardwareEntities = R.pipe(
          R.pathOr([], namePath),
          R.map((n) => {
            return {
              id: n.node.id,
              name: n.node.name || n.node.title,
            };
          }),
        )(data);
        this.setState({
          list: [...installedHardwareEntities],
        });
      });
  }

  handleSubmit() {
    const { data } = this.state;
    if (data.length === 0) {
      this.setState({ open: false });

      if (this.props.data !== data) {
        this.setState({ open: false });
        this.props.onSubmit(this.props.name, []);
      }
    } else {
      const finalOutput = data.length === 0
        ? []
        : data.map((item) => item.id);
      this.setState({ open: false });
      this.props.onSubmit(this.props.name, finalOutput);
    }
  }

  handleDelete(key) {
    this.setState(
      { data: this.state.data.filter((value, i) => i !== key) },
      () => {
        const finalOutput = this.state.data.length === 0
          ? []
          : this.state.data.map((item) => item.id);
        this.props.onDelete(this.props.name, finalOutput[0]);
      },
    );
  }

  handleSelectChange(event) {
    const { data } = this.state;
    const diagramId = event.target.value;
    this.setState({ value: diagramId });
    const addItem = R.find((n) => n.id === diagramId)(this.state.list);
    if (this.state.data.every((value) => value.id !== diagramId)) {
      this.setState({
        data: [...data, addItem],
        value: '',
        isSubmitting: false,
      });
    } else {
      this.setState({
        value: '',
        isSubmitting: false,
      });
    }
    this.props.onSubmit(this.props.name, diagramId);
  }

  render() {
    const {
      t,
      classes,
      name,
      history,
      title,
      onSubmit,
      variant,
      helperText,
      containerstyle,
      style,
    } = this.props;
    const systemImplementationData = this.props.data.length > 0
      ? R.map((n) => ({ id: n.id, name: n.name || n.title }))(this.props.data)
      : [];
    return (
      <>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <Typography variant='h3' color='textSecondary' gutterBottom={true}>
            {title && t(title)}
          </Typography>
          <div style={{ float: 'left', margin: '5px 0 0 5px' }}>
            <Tooltip title={t(helperText)}>
              <Information fontSize='inherit' color='disabled' />
            </Tooltip>
          </div>
          <IconButton
            size="small"
            onClick={() => this.setState({ open: true })}
          >
            <LinkIcon />
          </IconButton>
        </div>
        <Field
          component={HyperLinks}
          name={name}
          fullWidth={true}
          disabled={true}
          multiline={true}
          detach={true}
          rows='3'
          value={systemImplementationData}
          className={classes.textField}
          InputProps={{
            className: classes.inputTextField,
          }}
          variant='outlined'
          history={history}
          handleDelete={this.handleDelete.bind(this)}
        />
        <Dialog
          keepMounted={false}
          open={this.state.open}
          fullWidth={true}
          maxWidth='sm'
        >
          <DialogContent>{title && t(title)}</DialogContent>
          <DialogContent
            style={{
              overflow: 'hidden',
              display: 'flex',
              alignItems: 'center',
            }}
          >
            <FormControl variant='standard' style={containerstyle}>
              <InputLabel variant="standard" id='demo-simple-select-label'>Select {title}</InputLabel>
              <Select
                variant='standard'
                labelId='demo-simple-select-label'
                name={name}
                fullWidth={true}
                containerstyle={containerstyle}
                // disabled={disabled || false}
                // size={size}
                style={style}
                helperText={helperText}
                value={this.state.value}
                onOpen={this.handleSearchEntities.bind(this)}
                onChange={this.handleSelectChange.bind(this)}
                disableUnderline
              >
                {this.state.list.length > 0
                  && this.state.list.map((listItem) => listItem.name && (
                    <MenuItem key={listItem.id} value={listItem.id}>
                      {t(listItem.name)}
                    </MenuItem>
                  ))}
              </Select>
            </FormControl>
          </DialogContent>
          <DialogContent>
            <div className={classes.scrollBg}>
              <div className={classes.scrollDiv}>
                <div className={classes.scrollObj}>
                  {systemImplementationData.map((item, key) => (
                    <div key={key}>
                      <Typography>{item.name}</Typography>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </DialogContent>
          <DialogActions className={classes.dialogAction}>
            <Button
              variant='outlined'
              onClick={() => this.setState({ open: false, value: '', data: [] })}
            >
              {t('Cancel')}
            </Button>
            <Button
              disabled={this.state.isSubmitting}
              variant='contained'
              onClick={this.handleSubmit.bind(this)}
              color='primary'
            >
              {t('Submit')}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

SystemImplementationField.propTypes = {
  t: PropTypes.func,
  data: PropTypes.array,
  name: PropTypes.string,
  title: PropTypes.string,
  onSubmit: PropTypes.func,
  onDelete: PropTypes.func,
  classes: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(SystemImplementationField);
