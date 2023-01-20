import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import Table from '@mui/material/Table';
import TableHead from '@mui/material/TableHead';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import IconButton from '@mui/material/IconButton';
import {
  CheckCircleOutlined,
  ClearOutlined,
  DeleteOutlined,
  UnpublishedOutlined,
} from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import Chip from '@mui/material/Chip';
import DialogTitle from '@mui/material/DialogTitle';
import Alert from '@mui/material/Alert';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { defaultValue } from '../../../../utils/Graph';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';

const styles = (theme) => ({
  bottomNav: {
    padding: 0,
    zIndex: 1100,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithLargePadding: {
    zIndex: 1100,
    padding: '0 230px 0 0',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithMediumPadding: {
    zIndex: 1100,
    padding: '0 200px 0 0',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithSmallPadding: {
    zIndex: 1100,
    padding: '0 180px 0 0',
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
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '5px 10px 5px 0',
  },
  step: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.background.accent}`,
    borderRadius: 5,
    display: 'flex',
  },
  formControl: {
    width: '100%',
  },
  stepType: {
    margin: 0,
    paddingRight: 20,
    width: '30%',
  },
  stepField: {
    margin: 0,
    paddingRight: 20,
    width: '30%',
  },
  stepValues: {
    paddingRight: 20,
    margin: 0,
  },
  stepCloseButton: {
    position: 'absolute',
    top: -20,
    right: -20,
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

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const toolBarListTaskAddMutation = graphql`
  mutation ToolBarNotificationsListTaskAddMutation($input: ListTaskAddInput) {
    listTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const toolBarQueryTaskAddMutation = graphql`
  mutation ToolBarNotificationsQueryTaskAddMutation($input: QueryTaskAddInput) {
    queryTaskAdd(input: $input) {
      id
      type
    }
  }
`;

class ToolBar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayTask: false,
      actions: [],
      actionsInputs: [{}],
      processing: false,
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

  handleOpenTask() {
    this.setState({ displayTask: true });
  }

  handleCloseTask() {
    this.setState({
      displayTask: false,
      actions: [],
      keptEntityId: null,
      mergingElement: null,
      processing: false,
    });
  }

  handleLaunchRead(read) {
    const actions = [
      {
        type: 'REPLACE',
        context: { field: 'is_read', type: 'ATTRIBUTE', values: [read ? 'true' : 'false'] },
      },
    ];
    this.setState({ actions }, () => {
      this.handleOpenTask();
    });
  }

  handleLaunchDelete() {
    const actions = [{ type: 'DELETE', context: null }];
    this.setState({ actions }, () => {
      this.handleOpenTask();
    });
  }

  submitTask() {
    this.setState({ processing: true });
    const { actions, mergingElement } = this.state;
    const {
      filters,
      search,
      selectAll,
      selectedElements,
      deSelectedElements,
      numberOfSelectedElements,
      handleClearSelectedElements,
      t,
    } = this.props;
    if (numberOfSelectedElements === 0) return;
    const jsonFilters = JSON.stringify(filters);
    const finalActions = R.map(
      (n) => ({
        type: n.type,
        context: n.context
          ? {
            ...n.context,
            values: R.map((o) => o.id || o.value || o, n.context.values),
          }
          : null,
      }),
      actions,
    );
    if (selectAll) {
      commitMutation({
        mutation: toolBarQueryTaskAddMutation,
        variables: {
          input: {
            filters: jsonFilters,
            search,
            actions: finalActions,
            excluded_ids: Object.keys(deSelectedElements || {}),
          },
        },
        onCompleted: () => {
          handleClearSelectedElements();
          MESSAGING$.notifySuccess(
            <span>
              {t(
                'The background task has been executed. You can monitor it on',
              )}{' '}
              <Link to="/dashboard/data/tasks">{t('the dedicated page')}</Link>.
            </span>,
          );
          this.setState({ processing: false });
          this.handleCloseTask();
        },
      });
    } else {
      commitMutation({
        mutation: toolBarListTaskAddMutation,
        variables: {
          input: {
            ids: mergingElement
              ? [mergingElement.id]
              : Object.keys(selectedElements),
            actions: finalActions,
          },
        },
        onCompleted: () => {
          handleClearSelectedElements();
          MESSAGING$.notifySuccess(
            <span>
              {t(
                'The background task has been executed. You can monitor it on',
              )}{' '}
              <Link to="/dashboard/data/tasks">{t('the dedicated page')}</Link>.
            </span>,
          );
          this.setState({ processing: false });
          this.handleCloseTask();
        },
      });
    }
  }

  render() {
    const {
      t,
      n,
      classes,
      numberOfSelectedElements,
      handleClearSelectedElements,
      selectedElements,
      selectAll,
      filters,
      search,
      theme,
      variant,
      deleteDisable,
    } = this.props;
    const { actions, mergingElement, navOpen } = this.state;
    const isOpen = numberOfSelectedElements > 0;
    let paperClass;
    switch (variant) {
      case 'large':
        paperClass = classes.bottomNavWithLargePadding;
        break;
      case 'medium':
        paperClass = classes.bottomNavWithMediumPadding;
        break;
      case 'small':
        paperClass = classes.bottomNavWithSmallPadding;
        break;
      default:
        paperClass = classes.bottomNav;
    }
    return (
      <Drawer
        anchor="bottom"
        variant="persistent"
        classes={{ paper: paperClass }}
        open={isOpen}
        PaperProps={{
          variant: 'elevation',
          elevation: 1,
          style: { paddingLeft: navOpen ? 185 : 60 },
        }}
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
              disabled={numberOfSelectedElements === 0 || this.state.processing}
              onClick={handleClearSelectedElements.bind(this)}
              size="small"
            >
              <ClearOutlined fontSize="small" />
            </IconButton>
          </Typography>
          <Tooltip title={t('Mark as read')}>
            <span>
              <IconButton
                aria-label="ack"
                disabled={
                  numberOfSelectedElements === 0 || this.state.processing
                }
                onClick={this.handleLaunchRead.bind(this, true)}
                color="success"
                size="small"
              >
                <CheckCircleOutlined fontSize="small" />
              </IconButton>
            </span>
          </Tooltip>
          <Tooltip title={t('Mark as unread')}>
            <span>
              <IconButton
                aria-label="ack"
                disabled={
                  numberOfSelectedElements === 0 || this.state.processing
                }
                onClick={this.handleLaunchRead.bind(this, false)}
                color="warning"
                size="small"
              >
                <UnpublishedOutlined fontSize="small" />
              </IconButton>
            </span>
          </Tooltip>
          {deleteDisable !== true && (
            <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
              <Tooltip title={t('Delete')}>
                <span>
                  <IconButton
                    aria-label="delete"
                    disabled={
                      numberOfSelectedElements === 0 || this.state.processing
                    }
                    onClick={this.handleLaunchDelete.bind(this)}
                    color="primary"
                    size="small"
                  >
                    <DeleteOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            </Security>
          )}
        </Toolbar>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayTask}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseTask.bind(this)}
          fullWidth={true}
          maxWidth="md"
        >
          <DialogTitle>
            <div style={{ float: 'left' }}>{t('Launch a background task')}</div>
            <div style={{ float: 'right' }}>
              <span
                style={{
                  padding: '2px 5px 2px 5px',
                  marginRight: 5,
                  backgroundColor: theme.palette.secondary.main,
                  color: '#ffffff',
                }}
              >
                {n(numberOfSelectedElements)}
              </span>{' '}
              {t('selected element(s)')}
            </div>
          </DialogTitle>
          <DialogContent>
            {numberOfSelectedElements > 1000 && (
              <Alert severity="warning">
                {t(
                  "You're targeting more than 1000 entities with this background task, be sure of what you're doing!",
                )}
              </Alert>
            )}
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>#</TableCell>
                    <TableCell>{t('Step')}</TableCell>
                    <TableCell>{t('Field')}</TableCell>
                    <TableCell>{t('Values')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <TableRow>
                    <TableCell>
                      {' '}
                      <span
                        style={{
                          padding: '2px 5px 2px 5px',
                          marginRight: 5,
                          color:
                            theme.palette.mode === 'dark'
                              ? '#000000'
                              : '#ffffff',
                          backgroundColor: theme.palette.primary.main,
                        }}
                      >
                        1
                      </span>
                    </TableCell>
                    <TableCell>
                      <Chip label="SCOPE" />
                    </TableCell>
                    <TableCell>{t('N/A')}</TableCell>
                    <TableCell>
                      {selectAll ? (
                        <div className={classes.filters}>
                          {search && search.length > 0 && (
                            <span>
                              <Chip
                                classes={{ root: classes.filter }}
                                label={
                                  <div>
                                    <strong>{t('Search')}</strong>: {search}
                                  </div>
                                }
                              />
                              <Chip
                                classes={{ root: classes.operator }}
                                label={t('AND')}
                              />
                            </span>
                          )}
                          {R.map((currentFilter) => {
                            const label = `${truncate(
                              currentFilter[0].startsWith('rel_')
                                ? t(
                                  `relationship_${currentFilter[0]
                                    .replace('rel_', '')
                                    .replace('.*', '')}`,
                                )
                                : t(`filter_${currentFilter[0]}`),
                              20,
                            )}`;
                            const localFilterMode = currentFilter[0].endsWith(
                              'not_eq',
                            )
                              ? t('AND')
                              : t('OR');
                            const values = (
                              <span>
                                {R.map(
                                  (o) => (
                                    <span
                                      key={typeof o === 'string' ? o : o.value}
                                    >
                                      {/* eslint-disable-next-line no-nested-ternary */}
                                      {typeof o === 'string'
                                        ? o
                                        : o.value && o.value.length > 0
                                          ? truncate(o.value, 15)
                                          : t('No label')}{' '}
                                      {R.last(currentFilter[1]).value
                                        !== o.value && (
                                        <code>{localFilterMode}</code>
                                      )}{' '}
                                    </span>
                                  ),
                                  currentFilter[1],
                                )}
                              </span>
                            );
                            return (
                              <span key={currentFilter[0]}>
                                <Chip
                                  classes={{ root: classes.filter }}
                                  label={
                                    <div>
                                      <strong>{label}</strong>: {values}
                                    </div>
                                  }
                                />
                                {R.last(R.toPairs(filters))[0]
                                  !== currentFilter[0] && (
                                  <Chip
                                    classes={{ root: classes.operator }}
                                    label={t('AND')}
                                  />
                                )}
                              </span>
                            );
                          }, R.toPairs(filters))}
                        </div>
                      ) : (
                        <span>
                          {mergingElement
                            ? truncate(
                              R.join(', ', [defaultValue(mergingElement)]),
                              80,
                            )
                            : truncate(
                              R.join(
                                ', ',
                                R.map(
                                  (o) => defaultValue(o),
                                  R.values(selectedElements || {}),
                                ),
                              ),
                              80,
                            )}
                        </span>
                      )}
                    </TableCell>
                  </TableRow>
                  {R.map((o) => {
                    const number = actions.indexOf(o);
                    return (
                      <TableRow key={o.type}>
                        <TableCell>
                          {' '}
                          <span
                            style={{
                              padding: '2px 5px 2px 5px',
                              marginRight: 5,
                              color:
                                theme.palette.mode === 'dark'
                                  ? '#000000'
                                  : '#ffffff',
                              backgroundColor: theme.palette.primary.main,
                            }}
                          >
                            {number + 2}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Chip label={o.type} />
                        </TableCell>
                        <TableCell>
                          {R.pathOr(t('N/A'), ['context', 'field'], o)}
                        </TableCell>
                        <TableCell>
                          {truncate(
                            R.join(
                              ', ',
                              R.map(
                                (p) => (typeof p === 'string' ? p : defaultValue(p)),
                                R.pathOr([], ['context', 'values'], o),
                              ),
                            ),
                            80,
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  }, actions)}
                </TableBody>
              </Table>
            </TableContainer>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseTask.bind(this)}
              disabled={this.state.processing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitTask.bind(this)}
              color="secondary"
              disabled={this.state.processing}
            >
              {t('Launch')}
            </Button>
          </DialogActions>
        </Dialog>
      </Drawer>
    );
  }
}

ToolBar.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  numberOfSelectedElements: PropTypes.number,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
  filters: PropTypes.object,
  search: PropTypes.string,
  handleClearSelectedElements: PropTypes.func,
  variant: PropTypes.string,
  container: PropTypes.object,
  type: PropTypes.string,
  handleCopy: PropTypes.func,
};

export default R.compose(inject18n, withTheme, withStyles(styles))(ToolBar);
