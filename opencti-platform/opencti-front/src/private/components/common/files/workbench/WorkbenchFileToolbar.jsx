import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import {
  CenterFocusStrongOutlined,
  ClearOutlined,
  DeleteOutlined,
} from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import Slide from '@mui/material/Slide';
import { Form, Formik } from 'formik';
import DialogTitle from '@mui/material/DialogTitle';
import inject18n from '../../../../../components/i18n';
import ObjectMarkingField from '../../form/ObjectMarkingField';
import { UserContext } from '../../../../../utils/hooks/useAuth';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1040,
    padding: '0 0 0 180px',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  buttonAdd: {
    width: '100%',
    height: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  aliases: {
    margin: '0 7px 7px 0',
  },
  title: {
    flex: '1 1 100%',
    fontSize: '12px',
  },
  chipValue: {
    margin: 0,
  },
  filter: {
    margin: '5px 10px 5px 0',
  },
  formControl: {
    width: '100%',
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
});

class WorkbenchFileToolbar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDelete: false,
      displayApplyMarking: false,
    };
  }

  handleOpenApplyMarking() {
    this.setState({ displayApplyMarking: true });
  }

  handleCloseApplyMarking() {
    this.setState({
      displayApplyMarking: false,
    });
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
  }

  handleCloseDelete() {
    this.setState({
      displayDelete: false,
    });
  }

  onSubmitApplyMarking(values) {
    this.props.submitApplyMarking(values);
    this.handleCloseApplyMarking();
  }

  onResetApplyMarking() {
    this.handleCloseApplyMarking();
  }

  render() {
    const {
      t,
      classes,
      numberOfSelectedElements,
      handleClearSelectedElements,
      submitDelete,
      theme,
      rightOffset,
    } = this.props;
    const { displayDelete, displayApplyMarking } = this.state;
    const isOpen = numberOfSelectedElements > 0;
    const initialValues = { objectMarking: [] };
    return (
        <UserContext.Consumer>
          {({ bannerSettings }) => (
            <Drawer
              anchor="bottom"
              variant="persistent"
              classes={{
                // eslint-disable-next-line no-nested-ternary
                paper: classes.bottomNav,
              }}
              open={isOpen}
              PaperProps={{ variant: 'elevation', elevation: 1, style: { bottom: bannerSettings.bannerHeightNumber, paddingRight: rightOffset ?? 85 } }}
            >
              <Toolbar style={{ minHeight: 54 }}>
                <Typography
                  className={classes.title}
                  color="inherit"
                  variant="subtitle1"
                >
                  <span
                    style={{
                      padding: '2px 5px 2px 5px',
                      marginRight: 5,
                      backgroundColor: theme.palette.secondary.main,
                      color: '#ffffff',
                    }}
                  >
                    {numberOfSelectedElements}
                  </span>{' '}
                  {t('selected')}{' '}
                  <IconButton
                    aria-label="clear"
                    disabled={numberOfSelectedElements === 0}
                    onClick={handleClearSelectedElements.bind(this)}
                    size="large"
                  >
                    <ClearOutlined fontSize="small" />
                  </IconButton>
                </Typography>
                <IconButton
                  disabled={numberOfSelectedElements === 0}
                  onClick={this.handleOpenApplyMarking.bind(this)}
                  color="primary"
                  size="large"
                >
                  <CenterFocusStrongOutlined />
                </IconButton>
                <IconButton
                  disabled={numberOfSelectedElements === 0}
                  onClick={this.handleOpenDelete.bind(this)}
                  color="primary"
                  size="large"
                >
                  <DeleteOutlined />
                </IconButton>
              </Toolbar>
              <Dialog
                open={displayApplyMarking}
                PaperProps={{ elevation: 1 }}
                keepMounted={true}
                TransitionComponent={Transition}
                onClose={this.handleCloseApplyMarking.bind(this)}
                maxWidth="xs"
                fullWidth={true}
              >
                <DialogTitle>{t('Apply marking definitions')}</DialogTitle>
                <DialogContent>
                  <Formik
                    initialValues={initialValues}
                    onSubmit={this.onSubmitApplyMarking.bind(this)}
                    onReset={this.onResetApplyMarking.bind(this)}
                  >
                    {({ submitForm, handleReset, isSubmitting }) => (
                      <Form>
                        <ObjectMarkingField name="objectMarking" />
                        <div className={classes.buttons}>
                          <Button
                            onClick={handleReset}
                            disabled={isSubmitting}
                            classes={{ root: classes.button }}
                          >
                            {t('Cancel')}
                          </Button>
                          <Button
                            color="secondary"
                            onClick={submitForm}
                            disabled={isSubmitting}
                            classes={{ root: classes.button }}
                          >
                            {t('Update')}
                          </Button>
                        </div>
                      </Form>
                    )}
                  </Formik>
                </DialogContent>
              </Dialog>
              <Dialog
                open={displayDelete}
                PaperProps={{ elevation: 1 }}
                keepMounted={true}
                TransitionComponent={Transition}
                onClose={this.handleCloseDelete.bind(this)}
              >
                <DialogContent>
                  <DialogContentText>
                    {t('Do you want to remove these objects?')}
                  </DialogContentText>
                </DialogContent>
                <DialogActions>
                  <Button onClick={this.handleCloseDelete.bind(this)}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={() => {
                      this.handleCloseDelete();
                      submitDelete();
                    }}
                  >
                    {t('Remove')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Drawer>
          )}
        </UserContext.Consumer>
    );
  }
}

WorkbenchFileToolbar.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  numberOfSelectedElements: PropTypes.number,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
  search: PropTypes.string,
  handleClearSelectedElements: PropTypes.func,
  submitDelete: PropTypes.func,
  submitApplyMarking: PropTypes.func,
  rightOffset: PropTypes.number,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(WorkbenchFileToolbar);
