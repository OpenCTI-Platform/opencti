import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { CenterFocusStrongOutlined, ClearOutlined, DeleteOutlined } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Drawer from '@mui/material/Drawer';
import Slide from '@mui/material/Slide';
import Stack from '@mui/material/Stack';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import { styled } from '@mui/material/styles';
import { Form, Formik } from 'formik';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import React, { Component } from 'react';
import inject18n from '../../../../../components/i18n';
import { MESSAGING$ } from '../../../../../relay/environment';
import { UserContext } from '../../../../../utils/hooks/useAuth';
import withHooksSettingsMessagesBannerHeight from '../../../settings/settings_messages/withHooksSettingsMessagesBannerHeight';
import ObjectMarkingField from '../../form/ObjectMarkingField';
import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/navBarConstants';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const Buttons = styled('div')({
  marginTop: 20,
  textAlign: 'right',
});

class WorkbenchFileToolbar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDelete: false,
      displayApplyMarking: false,
      navOpen: localStorage.getItem('navOpen') === 'true',
    };
  }

  componentDidMount() {
    this.subscription = MESSAGING$.toggleNav.subscribe({
      next: () => this.setState({ navOpen: localStorage.getItem('navOpen') === 'true' }),
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
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

  onSubmitApplyMarking(values, { resetForm }) {
    this.props.submitApplyMarking(values, { resetForm });
    this.handleCloseApplyMarking();
  }

  onResetApplyMarking() {
    this.handleCloseApplyMarking();
  }

  render() {
    const {
      t,
      numberOfSelectedElements,
      handleClearSelectedElements,
      submitDelete,
    } = this.props;
    const { displayDelete, displayApplyMarking, navOpen } = this.state;
    const isOpen = numberOfSelectedElements > 0;
    const initialValues = { objectMarking: [] };
    return (
      <UserContext.Consumer>
        {({ bannerSettings }) => (
          <Drawer
            anchor="bottom"
            variant="persistent"
            open={isOpen}
            slotProps={{
              paper: {
                variant: 'elevation',
                elevation: 1,
                sx: {
                  zIndex: 1,
                  display: 'flex',
                  height: 50,
                  overflow: 'hidden',
                },
                style: {
                  paddingLeft: navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH,
                  bottom: bannerSettings.bannerHeightNumber,
                },
              },
            }}
          >
            <Toolbar style={{ minHeight: 54 }}>
              <Stack
                direction="row"
                sx={{
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  width: '100%',
                }}
              >
                <Stack
                  direction="row"
                  sx={{
                    alignItems: 'center',
                    gap: 1,
                  }}
                >
                  <Typography
                    variant="subtitle1"
                    sx={{
                      color: 'inherit',
                      flex: '1 1 100%',
                      fontSize: '12px',
                    }}
                  >
                    {`${numberOfSelectedElements} ${t('selected')}`}
                  </Typography>
                  <IconButton
                    aria-label="clear"
                    disabled={numberOfSelectedElements === 0}
                    onClick={handleClearSelectedElements.bind(this)}
                  >
                    <ClearOutlined />
                  </IconButton>
                </Stack>

                <Stack
                  direction="row"
                  sx={{
                    alignItems: 'center',
                    gap: 1,
                  }}
                >
                  <IconButton
                    aria-label={t('Apply marking')}
                    disabled={numberOfSelectedElements === 0}
                    onClick={this.handleOpenApplyMarking.bind(this)}
                  >
                    <CenterFocusStrongOutlined />
                  </IconButton>
                  <IconButton
                    aria-label={t('Delete')}
                    disabled={numberOfSelectedElements === 0}
                    onClick={this.handleOpenDelete.bind(this)}
                  >
                    <DeleteOutlined />
                  </IconButton>
                </Stack>
              </Stack>
            </Toolbar>
            <Dialog
              open={displayApplyMarking}
              onClose={this.handleCloseApplyMarking.bind(this)}
              title={t('Apply marking definitions')}
              size="small"
            >
              <Formik
                initialValues={initialValues}
                onSubmit={this.onSubmitApplyMarking.bind(this)}
                onReset={this.onResetApplyMarking.bind(this)}
              >
                {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
                  <Form>
                    <ObjectMarkingField name="objectMarking" setFieldValue={setFieldValue} />
                    <Buttons>
                      <Button
                        onClick={handleReset}
                        disabled={isSubmitting}
                        sx={{ marginLeft: 2 }}
                      >
                        {t('Cancel')}
                      </Button>
                      <Button
                        color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        sx={{ marginLeft: 2 }}
                      >
                        {t('Update')}
                      </Button>
                    </Buttons>
                  </Form>
                )}
              </Formik>
            </Dialog>
            <Dialog
              open={displayDelete}
              onClose={this.handleCloseDelete.bind(this)}
              title={t('Are you sure?')}
              size="small"
            >
              <DialogContentText>
                {t('Do you want to remove these objects?')}
              </DialogContentText>

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
                  {t('Confirm')}
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
  t: PropTypes.func,
  numberOfSelectedElements: PropTypes.number,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
  search: PropTypes.string,
  handleClearSelectedElements: PropTypes.func,
  submitDelete: PropTypes.func,
  submitApplyMarking: PropTypes.func,
};

export default R.compose(
  inject18n,
  withHooksSettingsMessagesBannerHeight,
)(WorkbenchFileToolbar);
