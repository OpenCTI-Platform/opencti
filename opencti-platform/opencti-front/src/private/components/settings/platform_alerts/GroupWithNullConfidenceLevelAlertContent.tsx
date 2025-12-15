import React, { Fragment } from 'react';
import DialogContentText from '@mui/material/DialogContentText';
import Box from '@mui/material/Box';
import { Link, useNavigate } from 'react-router-dom';
import DialogContent from '@mui/material/DialogContent';
import Button from '@common/button/Button';
import DialogActions from '@mui/material/DialogActions';
import { RootSettings$data } from '../../../__generated__/RootSettings.graphql';
import { useFormatter } from '../../../../components/i18n';

type GroupWithNullConfidenceLevelAlertContentProps = {
  alert: RootSettings$data['platform_critical_alerts'][0];
  closeHandler: () => void;
};

const GroupWithNullConfidenceLevelAlertContent: React.FC<GroupWithNullConfidenceLevelAlertContentProps> = ({ alert, closeHandler }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();

  const groups = (alert.details?.groups ?? []);
  const groupsExcerpt = groups.slice(0, 5);
  const restCount = Math.max(0, groups.length - 5);

  const goToSettingsHandler = () => {
    closeHandler();
    navigate('/dashboard/settings/accesses/groups');
  };

  return (
    <>
      <DialogContent>
        <DialogContentText sx={{ marginBottom: 3, whiteSpace: 'break-spaces' }}>
          {t_i18n(
            '',
            {
              id: `alert_${alert.type}`,
              values: {
                link_blogpost: <a href="https://blog.filigran.io/d10d7eb4407e">{t_i18n('this blogpost')}</a>,
                link_slack: <a href="https://filigran-community.slack.com">{t_i18n('our Slack channel')}</a>,
              },
            },
          )}
        </DialogContentText>
        { groupsExcerpt.length > 0 && (
          <DialogContentText>
            <Box component="span">{t_i18n('The following groups require your attention:')}</Box>
          &nbsp;
            {groupsExcerpt.map((user, index) => (
              <Fragment key={`${user.id}-${index}`}>
                <Link
                  to={`/dashboard/settings/accesses/groups/${user.id}`}
                  onClick={closeHandler}
                >
                  {user.name}
                </Link>
                {index !== groupsExcerpt.length - 1 && <span>,&nbsp;</span>}
              </Fragment>
            ))}
            { restCount > 0 && (
              <Box component="span" sx={{ marginLeft: 0.5 }}>
                { t_i18n('', { id: 'and ... more', values: { count: restCount } }) }
              </Box>
            )}
          </DialogContentText>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={goToSettingsHandler} color="secondary">
          {t_i18n('Open Settings')}
        </Button>
      </DialogActions>
    </>
  );
};

export default GroupWithNullConfidenceLevelAlertContent;
