import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import SettingsIcon from '@material-ui/icons/Settings';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import IconButton from '@material-ui/core/IconButton';
import Typography from '@material-ui/core/Typography';
import DialogContent from '@material-ui/core/DialogContent';
import FormControl from '@material-ui/core/FormControl';
import InputLabel from '@material-ui/core/InputLabel';
import Select from '@material-ui/core/Select';
import MenuItem from '@material-ui/core/MenuItem';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import { QueryRenderer } from '../../relay/environment';
import inject18n from '../../components/i18n';
import Loader from '../../components/Loader';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export const dashboardSettingsDashboardsQuery = graphql`
  query DashboardSettingsDashboardsQuery(
    $count: Int!
    $orderBy: WorkspacesOrdering
    $orderMode: OrderingMode
    $filters: [WorkspacesFiltering]
  ) {
    workspaces(
      first: $count
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const styles = (theme) => ({
  icon: {
    marginLeft: theme.spacing(1),
  },
  dialogRoot: {
    padding: '10px',
  },
});

class DashboardSettings extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  render() {
    const {
      t,
      classes,
      handleChangeDashboard,
      dashboard,
    } = this.props;
    const { open } = this.state;
    return (
      <span>
        <IconButton onClick={this.handleOpen.bind(this)} size="medium">
          <SettingsIcon color='primary' fontSize='small' />
        </IconButton>
        <Dialog
          open={open}
          PaperProps={{ elevation: 1 }}
          TransitionComponent={Transition}
          classes={{ paper: classes.dialogRoot }}
          maxWidth="sm"
          fullWidth={true}
        >
          <DialogTitle classes={{ root: classes.dialogTitle }}>
            {t('Dashboard Settings')}
            <Typography>
              {t("Choose from your organization's custom dashboards")}
            </Typography>
          </DialogTitle>
          <DialogContent>
            <QueryRenderer
              query={dashboardSettingsDashboardsQuery}
              variables={{
                count: 50,
                orderBy: 'name',
                orderMode: 'asc',
                filters: [{ key: 'type', values: ['dashboard'] }],
              }}
              render={({ props }) => {
                if (props) {
                  return (
                    <div>
                      <FormControl style={{ width: '100%' }}>
                        <InputLabel id="timeField" variant="standard">
                          {t('Current dashboard')}
                        </InputLabel>
                        <Select
                          labelId="dashboard"
                          variant="standard"
                          value={dashboard === null ? '' : dashboard}
                          onChange={handleChangeDashboard.bind(this)}
                          fullWidth={true}
                        >
                          <MenuItem value="default">{t('Default')}</MenuItem>
                          {props.workspaces.edges.map((workspaceEdge) => {
                            const workspace = workspaceEdge.node;
                            return (
                              <MenuItem
                                key={workspace.id}
                                value={workspace.id}
                              >
                                {workspace.name}
                              </MenuItem>
                            );
                          })}
                        </Select>
                      </FormControl>
                    </div>
                  );
                }
                return <Loader variant="inElement"/>;
              }}
            />
          </DialogContent>
          <DialogActions>
            <Button variant='outlined' onClick={this.handleClose.bind(this)}>{t('Close')}</Button>
          </DialogActions>
        </Dialog>
      </span>
    );
  }
}

DashboardSettings.propTypes = {
  me: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  handleChangeDashboard: PropTypes.func,
  dashboard: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(DashboardSettings);
