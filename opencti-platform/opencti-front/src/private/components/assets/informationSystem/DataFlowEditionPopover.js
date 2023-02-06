/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { withStyles } from '@material-ui/core/styles/index';
import { Formik, Form, Field } from 'formik';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import { Switch } from '@material-ui/core';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.background.paper,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  menuItem: {
    padding: '15px 0',
    width: '152px',
    margin: '0 20px',
    justifyContent: 'center',
  },
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogContent: {
    padding: '0 24px',
    marginBottom: '24px',
    overflowY: 'auto',
    overflowX: 'hidden',
  },
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
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
    height: '78px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  thumb: {
    '&.MuiSwitch-thumb': {
      color: 'white',
    },
  },
  switch_track: {
    backgroundColor: '#D3134A !important',
    opacity: '1 !important',
  },
  switch_base: {
    color: 'white',
    '&.Mui-checked + .MuiSwitch-track': {
      backgroundColor: '#49B8FC !important',
      opacity: 1,
    },
  },
});

export class DataFlowEditionPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      close: false,
    };
  }

  handleCancelOpenClick() {
    this.setState({ close: true });
  }

  handleCancelCloseClick() {
    this.setState({ close: false });
  }

  handleCloseMain() {
    this.setState({ close: false });
    this.props.handleCloseConnection();
  }

  render() {
    const {
      t,
      classes,
    } = this.props;
    return (
        <>
        <Dialog open={this.props.openEdit} keepMounted={true}>
          <DialogTitle classes={{ root: classes.dialogTitle }}>
            {t("Edit Data Flow")}
          </DialogTitle>
          <DialogContent classes={{ root: classes.dialogContent }}>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={12}>
                <div className={classes.textBase}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ margin: 0 }}
                  >
                    {t("Description")}
                  </Typography>
                  <Tooltip title={t("Description")}>
                    <Information
                      style={{ marginLeft: "5px" }}
                      fontSize="inherit"
                      color="disabled"
                    />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {/* Content here */}
                    </div>
                  </div>
                </div>
              </Grid>
              <Grid item={true} xs={12}>
                <div className={classes.textBase}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ margin: 0 }}
                  >
                    {t("Diagram(s)")}
                  </Typography>
                  <Tooltip title={t("Diagram(s)")}>
                    <Information
                      style={{ marginLeft: "5px" }}
                      fontSize="inherit"
                      color="disabled"
                    />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      {/* Content here */}
                    </div>
                  </div>
                </div>
              </Grid>
            </Grid>
          </DialogContent>
          <DialogActions classes={{ root: classes.dialogClosebutton }}>
            <Button
              variant="outlined"
              onClick={this.props.handleCloseEdit}
              classes={{ root: classes.buttonPopover }}
            >
              {t("Cancel")}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

DataFlowEditionPopover.propTypes = {
  t: PropTypes.func,
  fldt: PropTypes.func,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  dataSource: PropTypes.object,
  openConnection: PropTypes.bool,
  handleCloseConnection: PropTypes.func,
};


export default compose(inject18n, withStyles(styles))(DataFlowEditionPopover);
