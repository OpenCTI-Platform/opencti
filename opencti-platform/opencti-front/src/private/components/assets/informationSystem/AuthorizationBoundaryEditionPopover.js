/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose, pathOr } from 'ramda';
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
import MarkDownField from '../../../../components/MarkDownField';
import HyperLinkField from '../../common/form/HyperLinkField';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';

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
    // minWidth: '580px',
    minHeight: '550px',
  },
  dialogClosebutton: {
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

class AuthorizationBoundaryEdition extends Component {
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
      refreshQuery,
      informationSystem,
    } = this.props;
    const authorizationBoundary = pathOr([], ['authorization_boundary'], informationSystem);
    const initialValues = R.pipe(
      R.assoc('name', authorizationBoundary?.name || ''),
      R.assoc('description', authorizationBoundary?.description || ''),
      R.pick([
        'name',
        'description',
      ]),
    )(authorizationBoundary);
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
                      <Typography>
                        {t("Identifies a description of this system's authorization boundary, optionally supplemented by diagrams that illustrate the authorization boundary.")}
                      </Typography>
                    </Grid>
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
                    <Grid item={true} xs={12}>
                      <CyioCoreObjectExternalReferences
                        externalReferences={authorizationBoundary.links}
                        cyioCoreObjectId={authorizationBoundary.id}
                        fieldName='links'
                        refreshQuery={refreshQuery}
                        typename={authorizationBoundary.__typename}
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

AuthorizationBoundaryEdition.propTypes = {
  t: PropTypes.func,
  fldt: PropTypes.func,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  dataSource: PropTypes.object,
  openConnection: PropTypes.bool,
  handleCloseConnection: PropTypes.func,
};

const AuthorizationBoundaryEditionPopover = createFragmentContainer(AuthorizationBoundaryEdition, {
  informationSystem: graphql`
    fragment AuthorizationBoundaryEditionPopover_information on InformationSystem {
      __typename
      id
      authorization_boundary {
        id
        entity_type
        description
        diagrams {
          id
          entity_type
          created
          modified
          description
          caption
          diagram_link
        }
        links {
          id
          entity_type
          created
          modified
          source_name
          description
          url
          external_id
          reference_purpose
          media_type
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(AuthorizationBoundaryEditionPopover);
