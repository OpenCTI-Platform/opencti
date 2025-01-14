import makeStyles from '@mui/styles/makeStyles';
import React, { useState } from 'react';
import FeedbackCreation from '@components/cases/feedbacks/FeedbackCreation';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { createStyles, useTheme } from '@mui/styles';
import IconButton from '@mui/material/IconButton';
import { AutoAwesomeOutlined, Close } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import Drawer from '@mui/material/Drawer';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import AISummaryActivity from '@components/common/ai/AISummaryActivity';
import AISummaryContainers from '@components/common/ai/AISummaryContainers';
import AISummaryHistory from '@components/common/ai/AISummaryHistory';
import AISummaryForecast from '@components/common/ai/AISummaryForecast';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';
import useAI from '../../../../utils/hooks/useAI';
import { aiName, aiUrl } from '../../../../utils/ai/Common';
import useFiltersState from '../../../../utils/filters/useFiltersState';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme, { bannerHeightNumber: number }>((theme) => createStyles({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    paddingTop: ({ bannerHeightNumber }) => `${bannerHeightNumber}px`,
    paddingBottom: ({ bannerHeightNumber }) => `${bannerHeightNumber}px`,
  },
  header: {
    backgroundColor: theme.palette.mode === 'light' ? theme.palette.background.default : theme.palette.background.nav,
    padding: '10px 0',
    display: 'inline-flex',
    alignItems: 'center',
  },
  container: {
    padding: theme.spacing(2),
    height: '100%',
    overflowY: 'auto',
  },
  chip: {
    fontSize: 'x-small',
    display: 'inline-flex',
    fontWeight: 600,
    justifyContent: 'center',
    alignItems: 'center',
    marginLeft: 6,
    borderRadius: theme.borderRadius,
    border: `1px solid ${theme.palette.ai.main}`,
    color: theme.palette.ai.main,
    backgroundColor: theme.palette.ai.background,
    cursor: 'pointer',
    '&:hover': {
      border: `1px solid ${theme.palette.ai.light}`,
      color: theme.palette.ai.light,
    },
  },
  chipFloating: {
    float: 'right',
    fontSize: 'x-small',
    fontWeight: 600,
    height: 25,
    display: 'inline-flex',
    justifyContent: 'center',
    alignItems: 'center',
    marginTop: -7,
    marginLeft: 6,
    borderRadius: theme.borderRadius,
    border: `1px solid ${theme.palette.ai.main}`,
    color: theme.palette.ai.main,
    backgroundColor: theme.palette.ai.background,
    cursor: 'pointer',
    '&:hover': {
      border: `1px solid ${theme.palette.ai.light}`,
      color: theme.palette.ai.light,
    },
  },
}));

interface AIInsightProps {
  id: string
  tabs?: Array<'activity' | 'containers' | 'forecast' | 'history'>
  defaultTab?: 'activity' | 'containers' | 'forecast' | 'history'
  floating?: boolean
  onlyIcon?: boolean
  isContainer?: boolean;
}

const AIInsights = ({
  id,
  tabs = ['activity', 'containers', 'forecast', 'history'],
  defaultTab = 'activity',
  floating = false,
  onlyIcon = false,
  isContainer = false,
}: AIInsightProps) => {
  const theme = useTheme<Theme>();
  const { bannerSettings: { bannerHeightNumber }, settings: { id: settingsId } } = useAuth();
  const classes = useStyles({ bannerHeightNumber });
  const isEnterpriseEdition = useEnterpriseEdition();
  const { fullyActive } = useAI();
  const { t_i18n } = useFormatter();
  const [display, setDisplay] = useState(false);
  const [displayEEDialog, setDisplayEEDialog] = useState(false);
  const [displayAIDialog, setDisplayAIDialog] = useState(false);
  const [currentTab, setCurrentTab] = useState(defaultTab);
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);

  const handleChangeTab = (_: React.SyntheticEvent, newValue: 'activity' | 'containers' | 'forecast' | 'history') => {
    setCurrentTab(newValue);
  };

  const initialContainersFilters = isContainer ? {
    mode: 'and',
    filters: [{
      key: 'id',
      values: [id],
    }],
    filterGroups: [],
  } : {
    mode: 'and',
    filters: [{
      key: 'entity_type',
      values: ['Report', 'Case', 'Observed-Data', 'Grouping', 'Task'],
    },
    {
      key: 'objects',
      values: [id],
    }],
    filterGroups: [],
  };
  // TODO make the filter "objects" readonly?
  const [containersFilters, containersFiltersHelpers] = useFiltersState(initialContainersFilters);
  if (!isEnterpriseEdition) {
    return (
      <>
        <Tooltip title={t_i18n('AI Insights')}>
          {onlyIcon ? (
            <IconButton
              size="small"
              style={{
                fontSize: 12,
                color: theme.palette.ai.main,
              }}
              onClick={() => setDisplayEEDialog(true)}
              className={floating ? classes.chipFloating : classes.chip}
            >
              <AutoAwesomeOutlined style={{ fontSize: 14 }} />
            </IconButton>
          ) : (
            <Button
              variant="outlined"
              size="small"
              style={{
                fontSize: 12,
                color: theme.palette.ai.main,
              }}
              onClick={() => setDisplayEEDialog(true)}
              className={floating ? classes.chipFloating : classes.chip}
              startIcon={<AutoAwesomeOutlined style={{ fontSize: 14 }} />}
            >
              {t_i18n('AI Insights')}
            </Button>
          )}
        </Tooltip>
        {isAdmin ? (
          <EnterpriseEditionAgreement
            open={displayEEDialog}
            onClose={() => setDisplayEEDialog(false)}
            settingsId={settingsId}
          />
        ) : (
          <FeedbackCreation
            openDrawer={displayEEDialog}
            handleCloseDrawer={() => setDisplayEEDialog(false)}
            initialValue={{
              description: t_i18n('I would like to use a EE feature AI Summary but I don\'t have EE activated.\nI would like to discuss with you about activating EE.'),
            }}
          />
        )}
      </>
    );
  }
  if (!fullyActive) {
    return (
      <>
        <Tooltip title={t_i18n('AI Insights')}>
          {onlyIcon ? (
            <IconButton
              size="small"
              style={{
                fontSize: 12,
                color: theme.palette.ai.main,
              }}
              onClick={() => setDisplayAIDialog(true)}
              className={floating ? classes.chipFloating : classes.chip}
            >
              <AutoAwesomeOutlined style={{ fontSize: 14 }} />
            </IconButton>
          ) : (
            <Button
              variant="outlined"
              size="small"
              style={{
                fontSize: 12,
                color: theme.palette.ai.main,
              }}
              onClick={() => setDisplayAIDialog(true)}
              className={floating ? classes.chipFloating : classes.chip}
              startIcon={<AutoAwesomeOutlined style={{ fontSize: 14 }} />}
            >
              {t_i18n('AI Insights')}
            </Button>
          )}
        </Tooltip>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={displayAIDialog}
          onClose={() => setDisplayAIDialog(false)}
          fullWidth={true}
          maxWidth="sm"
        >
          <DialogTitle>
            {t_i18n('Enable AI powered platform')}
          </DialogTitle>
          <DialogContent>
            {t_i18n('To use AI, please enable it in the configuration of your platform.')}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDisplayAIDialog(false)}>{t_i18n('Close')}</Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
  return (
    <>
      <Tooltip title={t_i18n('AI Insights')}>
        {onlyIcon ? (
          <IconButton
            size="small"
            style={{
              fontSize: 12,
              color: theme.palette.ai.main,
            }}
            onClick={() => setDisplay(true)}
            className={floating ? classes.chipFloating : classes.chip}
          >
            <AutoAwesomeOutlined style={{ fontSize: 14 }} />
          </IconButton>
        ) : (
          <Button
            variant="outlined"
            size="small"
            style={{
              fontSize: 12,
              color: theme.palette.ai.main,
            }}
            onClick={() => setDisplay(true)}
            className={floating ? classes.chipFloating : classes.chip}
            startIcon={<AutoAwesomeOutlined style={{ fontSize: 14 }} />}
          >
            {t_i18n('AI Insights')}
          </Button>
        )}
      </Tooltip>
      <Drawer
        open={display}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={() => setDisplay(false)}
        onClick={(e) => e.stopPropagation()}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            onClick={() => setDisplay(false)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary"/>
          </IconButton>
          <Typography variant="subtitle2" style={{ textWrap: 'nowrap' }}>
            {t_i18n('AI Insights')}
          </Typography>
          <Typography variant="caption" style={{
            display: 'flex',
            alignItems: 'center',
            textWrap: 'nowrap',
            position: 'absolute',
            right: 10,
          }}
          >
            {t_i18n('Powered by')}&nbsp;<a href={aiUrl} target='_blank' rel='noreferrer'>{aiName}</a>
            <Chip label="beta" color="secondary" size="small" style={{ marginLeft: 10, borderRadius: 4, fontSize: 10 }} />
          </Typography>
        </div>
        <div className={classes.container}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={handleChangeTab}>
              {tabs.includes('activity') && <Tab value="activity" label={t_i18n('Activity')} />}
              {tabs.includes('containers') && <Tab value="containers" label={isContainer ? t_i18n('Container summary') : t_i18n('Latest containers')} />}
              {tabs.includes('forecast') && <Tab value="forecast" label={t_i18n('Forecast')} />}
              {tabs.includes('history') && <Tab value="history" label={t_i18n('Internal history')} />}
            </Tabs>
          </Box>
          {currentTab === 'activity' && (
            <AISummaryActivity id={id} />
          )}
          {currentTab === 'containers' && (
            <AISummaryContainers
              first={isContainer ? 1 : 10}
              filters={containersFilters}
              helpers={containersFiltersHelpers}
            />
          )}
          {currentTab === 'forecast' && (
            <AISummaryForecast id={id} />
          )}
          {currentTab === 'history' && (
            <AISummaryHistory id={id} />
          )}
        </div>
      </Drawer>
    </>
  );
};

export default AIInsights;
