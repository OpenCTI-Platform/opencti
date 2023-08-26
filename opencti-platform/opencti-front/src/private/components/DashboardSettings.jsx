import { SettingsOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import FormControl from '@mui/material/FormControl';
import IconButton from '@mui/material/IconButton';
import InputLabel from '@mui/material/InputLabel';
import ListSubheader from '@mui/material/ListSubheader';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import Slide from '@mui/material/Slide';
import React, { useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import ListItemIcon from '@mui/material/ListItemIcon';
import { useFormatter } from '../../components/i18n';
import { QueryRenderer } from '../../relay/environment';
import useAuth from '../../utils/hooks/useAuth';
import { EXPLORE } from '../../utils/hooks/useGranted';
import Security from '../../utils/Security';
import ItemIcon from '../../components/ItemIcon';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export const dashboardSettingsDashboardsQuery = graphql`
  query DashboardSettingsDashboardsQuery(
    $count: Int!
    $orderBy: WorkspacesOrdering
    $orderMode: OrderingMode
    $filters: [WorkspacesFiltering!]
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

const dashboardSettingsMutation = graphql`
  mutation DashboardSettingsMutation($input: [EditInput]!) {
    meEdit(input: $input) {
      ...DashboardMeFragment
    }
  }
`;

const DashboardSettings = () => {
  const { t } = useFormatter();
  const {
    me: {
      default_time_field: timeField,
      default_dashboard: dashboard,
      default_dashboards: dashboards,
    },
  } = useAuth();
  const [open, setOpen] = useState(false);
  const [updateDashboard] = useMutation(dashboardSettingsMutation);
  const handleUpdate = (name, newValue) => {
    let value = newValue;
    if (value === 'default') {
      value = '';
    }
    updateDashboard({ variables: { input: [{ key: name, value }] } });
  };
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  return (
    <span>
      <IconButton onClick={handleOpen} size="medium">
        <SettingsOutlined fontSize="small" />
      </IconButton>
      <Dialog
        open={open}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleClose}
        maxWidth="xs"
        fullWidth={true}
      >
        <DialogTitle>{t('Dashboard settings')}</DialogTitle>
        <DialogContent>
          <Security
            needs={[EXPLORE]}
            placeholder={
              <FormControl style={{ width: '100%' }}>
                <InputLabel id="timeField">{t('Date reference')}</InputLabel>
                <Select
                  labelId="timeField"
                  value={timeField === null ? '' : timeField}
                  onChange={(event) => handleUpdate('default_time_field', event.target.value)
                  }
                  fullWidth={true}
                >
                  <MenuItem value="technical">{t('Technical date')}</MenuItem>
                  <MenuItem value="functional">{t('Functional date')}</MenuItem>
                </Select>
              </FormControl>
            }
          >
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
                  const workspaces = props.workspaces.edges.filter(
                    ({ node: { id } }) => !dashboards.some((d) => d.id === id),
                  );
                  return (
                    <div>
                      <FormControl style={{ width: '100%' }}>
                        <InputLabel id="timeField">
                          {t('Date reference')}
                        </InputLabel>
                        <Select
                          labelId="timeField"
                          value={timeField ?? 'technical'}
                          onChange={(event) => handleUpdate(
                            'default_time_field',
                            event.target.value,
                          )
                          }
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
                          value={dashboard?.id ?? 'default'}
                          onChange={(event) => handleUpdate(
                            'default_dashboard',
                            event.target.value,
                          )
                          }
                          fullWidth={true}
                        >
                          <MenuItem value="default">
                            <em>{t('Automatic')}</em>
                          </MenuItem>
                          {dashboards?.length > 0 && (
                            <ListSubheader>
                              {t('Recommended dashboards')}
                            </ListSubheader>
                          )}
                          {dashboards?.map(({ id, name }) => (
                            <MenuItem key={id} value={id}>
                              <ListItemIcon>
                                <ItemIcon type="Dashboard" variant="inline" />
                              </ListItemIcon>
                              {name}
                            </MenuItem>
                          ))}
                          {workspaces?.length > 0 && (
                            <ListSubheader>{t('Dashboards')}</ListSubheader>
                          )}
                          {workspaces?.map(({ node }) => (
                            <MenuItem key={node.id} value={node.id}>
                              <ListItemIcon>
                                <ItemIcon type="Dashboard" />
                              </ListItemIcon>
                              {node.name}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    </div>
                  );
                }
                return <div />;
              }}
            />
          </Security>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>{t('Close')}</Button>
        </DialogActions>
      </Dialog>
    </span>
  );
};

export default DashboardSettings;
