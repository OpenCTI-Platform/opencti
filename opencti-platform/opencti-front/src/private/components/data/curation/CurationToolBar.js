import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Toolbar from '@material-ui/core/Toolbar';
import Typography from '@material-ui/core/Typography';
import Tooltip from '@material-ui/core/Tooltip';
import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableContainer from '@material-ui/core/TableContainer';
import TableRow from '@material-ui/core/TableRow';
import IconButton from '@material-ui/core/IconButton';
import { Delete } from '@material-ui/icons';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import Chip from '@material-ui/core/Chip';
import DialogTitle from '@material-ui/core/DialogTitle';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1000,
    padding: '0 230px 0 180px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    height: 50,
  },
  title: {
    flex: '1 1 100%',
    fontSize: '12px',
  },
  chipValue: {
    margin: 0,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const curationToolBarListTaskAddMutation = graphql`
  mutation CurationToolBarListTaskAddMutation($input: ListTaskAddInput) {
    listTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const curationToolBarQueryTaskAddMutation = graphql`
  mutation CurationToolBarQueryTaskAddMutation($input: QueryTaskAddInput) {
    queryTaskAdd(input: $input) {
      id
      type
    }
  }
`;

class CurationToolBar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayTask: false,
      displayAdd: false,
      displayReplace: false,
      displayMerge: false,
      taskType: null,
      mergeKeptEntityId: null,
      processing: false,
    };
  }

  handleOpenTask() {
    this.setState({ displayTask: true });
  }

  handleCloseTask() {
    this.setState({ displayTask: false });
  }

  handleOpenAdd() {
    this.setState({ displayAdd: true });
  }

  handleCloseAdd() {
    this.setState({ displayAdd: false });
  }

  handleOpenReplace() {
    this.setState({ displayReplace: true });
  }

  handleCloseReplace() {
    this.setState({ displayReplace: false });
  }

  handleOpenMerge() {
    this.setState({ displayMerge: true });
  }

  handleCloseMerge() {
    this.setState({ displayMerge: false });
  }

  launchTask(type) {
    this.setState({ taskType: type }, () => {
      if (type === 'ADD') {
        this.handleOpenAdd();
      } else if (type === 'REPLACE') {
        this.handleOpenReplace();
      } else if (type === 'MERGE') {
        this.handleOpenMerge();
      } else if (type === 'DELETE') {
        this.handleOpenTask();
      }
    });
  }

  submitTask() {
    const { definedTask } = this.state;
    console.log(definedTask);
  }

  render() {
    const {
      t,
      n,
      classes,
      numberOfSelectedElements,
      selectAll,
      filters,
    } = this.props;
    const { taskType } = this.state;
    const isOpen = numberOfSelectedElements > 0;
    return (
      <Drawer
        anchor="bottom"
        variant="persistent"
        classes={{ paper: classes.bottomNav }}
        open={isOpen}
      >
        <Toolbar style={{ minHeight: 54 }}>
          <Typography
            className={classes.title}
            color="inherit"
            variant="subtitle1"
          >
            {numberOfSelectedElements} {t('selected')}
          </Typography>
          <Tooltip title={t('Delete')}>
            <span>
              <IconButton
                aria-label="delete"
                disabled={
                  numberOfSelectedElements === 0 || this.state.processing
                }
                onClick={this.launchTask.bind(this, 'DELETE')}
                color="primary"
              >
                <Delete />
              </IconButton>
            </span>
          </Tooltip>
        </Toolbar>
        <Dialog
          open={this.state.displayTask}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseTask.bind(this)}
        >
          <DialogTitle>{t('Launch a background task')}</DialogTitle>
          <DialogContent>
            <DialogContentText>
              <TableContainer>
                <Table>
                  <TableBody>
                    <TableRow>
                      <TableCell>{t('Target')}</TableCell>
                      <TableCell>
                        {selectAll
                          ? t('Filtered query')
                          : t('List of entities')}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>{t('Filters')}</TableCell>
                      <TableCell>
                        {selectAll ? (
                          <div className={classes.filters}>
                            {R.map((currentFilter) => {
                              const label = `${truncate(
                                t(`filter_${currentFilter[0]}`),
                                20,
                              )}`;
                              const values = (
                                <span>
                                  {R.map(
                                    (o) => (
                                      <span key={o.value}>
                                        {o.value && o.value.length > 0
                                          ? truncate(o.value, 15)
                                          : t('No label')}{' '}
                                        {R.last(currentFilter[1]).value
                                          !== o.value && <code>OR</code>}{' '}
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
                          t('List of IDs')
                        )}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>{t('Number of elements')}</TableCell>
                      <TableCell>{n(numberOfSelectedElements)}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>{t('Type of task')}</TableCell>
                      <TableCell>
                        <Chip
                          classes={{ root: classes.chipValue }}
                          label={taskType}
                        />
                      </TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseTask.bind(this)}
              color="primary"
              disabled={this.state.processing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitTask.bind(this)}
              color="primary"
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

CurationToolBar.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  numberOfSelectedElements: PropTypes.number,
  selectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
  filters: PropTypes.object,
  handleClearSelectedElements: PropTypes.func,
};

export default R.compose(inject18n, withStyles(styles))(CurationToolBar);
