import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { SettingsOutlined } from '@material-ui/icons';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import IconButton from '@material-ui/core/IconButton';
import DialogContent from '@material-ui/core/DialogContent';
import FormControl from '@material-ui/core/FormControl';
import InputLabel from '@material-ui/core/InputLabel';
import Select from '@material-ui/core/Select';
import MenuItem from '@material-ui/core/MenuItem';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer } from '../../relay/environment';
import inject18n from '../../components/i18n';

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
      handleChangeTimeField,
      timeField,
      handleChangeDashboard,
      dashboard,
    } = this.props;
    const { open } = this.state;
    return (
      <span>
        <IconButton onClick={this.handleOpen.bind(this)} size="small">
          <SettingsOutlined fontSize="small" />
        </IconButton>
        <Dialog
          open={open}
          TransitionComponent={Transition}
          onClose={this.handleClose.bind(this)}
          maxWidth="xs"
          fullWidth={true}
        >
          <DialogTitle>{t('Dashboard settings')}</DialogTitle>
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
                        <InputLabel id="timeField">
                          {t('Date reference')}
                        </InputLabel>
                        <Select
                          labelId="timeField"
                          value={timeField === null ? '' : timeField}
                          onChange={handleChangeTimeField.bind(this)}
                          fullWidth={true}
                        >
                          <MenuItem value="technical">
                            {t('Technical date')}
                          </MenuItem>
                          <MenuItem value="functional">
                            {t('Functional date')}
                          </MenuItem>
                        </Select>
                      </FormControl>
                      <FormControl style={{ width: '100%', marginTop: 20 }}>
                        <InputLabel id="timeField">
                          {t('Custom dashboard')}
                        </InputLabel>
                        <Select
                          labelId="dashboard"
                          value={dashboard === null ? '' : dashboard}
                          onChange={handleChangeDashboard.bind(this)}
                          fullWidth={true}
                        >
                          <MenuItem value="default">{t('Default')}</MenuItem>
                          {props.workspaces.edges.map((workspaceEdge) => {
                            const workspace = workspaceEdge.node;
                            return (
                              <MenuItem key={workspace.id} value={workspace.id}>
                                {workspace.name}
                              </MenuItem>
                            );
                          })}
                        </Select>
                      </FormControl>
                    </div>
                  );
                }
                return <div />;
              }}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={this.handleClose.bind(this)}>{t('Close')}</Button>
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
  handleChangeTimeField: PropTypes.func,
  timeField: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(DashboardSettings);
