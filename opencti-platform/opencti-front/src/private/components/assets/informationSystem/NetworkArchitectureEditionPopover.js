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
import inject18n from '../../../../components/i18n';
import HyperLinkField from '../../common/form/HyperLinkField';
import MarkDownField from '../../../../components/MarkDownField';

const styles = (theme) => ({
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
    minWidth: '580px',
    minHeight: '550px',
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
});

class NetworkArchitectureComponent extends Component {
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
      informationSystem,
    } = this.props;
    const initialValues = R.pipe(
      R.assoc('name', informationSystem?.name || ''),
      R.assoc('description', informationSystem?.description || ''),
      R.pick([
        'name',
        'description',
      ]),
    )(informationSystem);
    return (
      <>
      <Dialog open={this.props.openEdit} keepMounted={true}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          // onSubmit={this.onSubmit.bind(this)}
          // onReset={this.onReset.bind(this)}
        >
          {({
            isSubmitting,
            setFieldValue,
          }) => (
            <Form>
              <DialogTitle classes={{ root: classes.dialogTitle }}>
                {t('Edit Authorization Boundary')}
              </DialogTitle>
              <DialogContent classes={{ root: classes.dialogContent }}>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={12}>
                    <div className={classes.textBase}>
                      <Typography variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Description')}
                      </Typography>
                      <Tooltip title={t('Description')}>
                        <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={MarkDownField}
                      name="description"
                      fullWidth={true}
                      multiline={true}
                      rows="4"
                      variant='outlined'
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <HyperLinkField
                      variant='outlined'
                      type='hardware'
                      multiple={true}
                      name="installed_hardware"
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '90%' }}
                      helperText={'Indicates installed hardware on this entity.'}
                      data={[]}
                      title={'Diagram(s)'}
                      setFieldValue={setFieldValue}
                      link='/defender HQ/assets/devices'
                    />
                  </Grid>
                </Grid>
              </DialogContent>
              <DialogActions classes={{ root: classes.dialogClosebutton }}>
                <Button
                  variant="outlined"
                  onClick={this.props.handleCloseEdit}
                  classes={{ root: classes.buttonPopover }}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="primary"
                  // onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.buttonPopover }}
                >
                  {t('Submit')}
                </Button>
              </DialogActions>
              <Dialog
                open={this.state.close}
                keepMounted={true}
              >
                <DialogContent>
                  <Typography className={classes.popoverDialog}>
                    {t('Are you sure you’d like to cancel?')}
                  </Typography>
                  <Typography align='left'>
                    {t('Your progress will not be saved')}
                  </Typography>
                </DialogContent>
                <DialogActions className={classes.dialogActions}>
                  <Button
                    onClick={this.handleCancelCloseClick.bind(this)}
                    classes={{ root: classes.buttonPopover }}
                    variant='outlined'
                    size='small'
                  >
                    {t('Go Back')}
                  </Button>
                  <Button
                    onClick={this.handleCloseMain.bind(this)}
                    color='secondary'
                    classes={{ root: classes.buttonPopover }}
                    variant='contained'
                    size='small'
                  >
                    {t('Yes, Cancel')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
      </Dialog>
    </>
    );
  }
}

NetworkArchitectureComponent.propTypes = {
  t: PropTypes.func,
  fldt: PropTypes.func,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  dataSource: PropTypes.object,
  openConnection: PropTypes.bool,
  handleCloseConnection: PropTypes.func,
};

const NetworkArchitectureEditionPopover = createFragmentContainer(NetworkArchitectureComponent, {
  informationSystem: graphql`
    fragment NetworkArchitectureEditionPopover_information on SoftwareAsset {
      id
      software_identifier
      license_key
      cpe_identifier
      patch_level
      installation_id
      implementation_point
      last_scanned
      is_scanned
      installed_on {
        id
        entity_type
        vendor_name
        name
        version
      }
      related_risks {
        id
        name
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(NetworkArchitectureEditionPopover);
