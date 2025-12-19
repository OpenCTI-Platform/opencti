import makeStyles from '@mui/styles/makeStyles';
import React, { useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@mui/material/Dialog';
import { createStyles } from '@mui/styles';
import { Close } from '@mui/icons-material';
import { LogoXtmOneIcon } from 'filigran-icon';
import Typography from '@mui/material/Typography';
import Drawer from '@mui/material/Drawer';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import AISummaryActivity from '@components/common/ai/AISummaryActivity';
import AISummaryContainers from '@components/common/ai/AISummaryContainers';
import AISummaryHistory from '@components/common/ai/AISummaryHistory';
import AISummaryForecast from '@components/common/ai/AISummaryForecast';
import { v4 as uuid } from 'uuid';
import FiligranIcon from '@components/common/FiligranIcon';
import FeedbackCreation from '@components/cases/feedbacks/FeedbackCreation';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import useAI from '../../../../utils/hooks/useAI';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';

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
    display: 'inline-flex',
    fontWeight: 500,
    justifyContent: 'center',
    alignItems: 'center',
    fontSize: 12,
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
    fontSize: 12,
    fontWeight: 500,
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
  chipNoAction: {
    display: 'flex',
    alignItems: 'center',
    textWrap: 'nowrap',
    position: 'absolute',
    right: 10,
    fontWeight: 500,
    justifyContent: 'center',
    fontSize: 12,
    marginLeft: 6,
    borderRadius: theme.borderRadius,
    border: `1px solid ${theme.palette.ai.main}`,
    color: theme.palette.ai.main,
    backgroundColor: theme.palette.ai.background,
    cursor: 'default',
    '&:hover': {
      border: `1px solid ${theme.palette.ai.light}`,
      color: theme.palette.ai.light,
    },
  },
}));

interface AIInsightProps {
  id: string;
  tabs?: Array<'activity' | 'containers' | 'forecast' | 'history'>;
  defaultTab?: 'activity' | 'containers' | 'forecast' | 'history';
  floating?: boolean;
  onlyIcon?: boolean;
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
  const { bannerSettings: { bannerHeightNumber }, settings: { id: settingsId } } = useAuth();
  const classes = useStyles({ bannerHeightNumber });
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const [display, setDisplay] = useState(false);
  const [displayEEDialog, setDisplayEEDialog] = useState(false);
  const [displayAIDialog, setDisplayAIDialog] = useState(false);
  const [currentTab, setCurrentTab] = useState(defaultTab);
  const [containersBusId] = useState(uuid());
  const [loading, setLoading] = useState(false);
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);

  const { fullyActive, enabled } = useAI();
  const handleClose = () => {
    setLoading(false);
    setDisplay(false);
  };
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
      values: ['Report', 'Case-Incident'],
    },
    {
      key: 'objects',
      values: [id],
    }],
    filterGroups: [],
  };
  // TODO make the filter "objects" readonly?
  const [containersFilters, containersFiltersHelpers] = useFiltersState(initialContainersFilters);
  if (!enabled) return null;
  if (!isEnterpriseEdition && enabled) {
    return (
      <>
        <Tooltip title={t_i18n('AI Insights')}>
          {onlyIcon ? (
            <IconButton
              size="small"
              onClick={() => setDisplayEEDialog(true)}
              className={floating ? classes.chipFloating : classes.chip}
            >
              <FiligranIcon icon={LogoXtmOneIcon} size="small" color="ai" />
            </IconButton>
          ) : (
            <Button
              variant="secondary"
              size="small"
              onClick={() => setDisplayEEDialog(true)}
              className={floating ? classes.chipFloating : classes.chip}
              startIcon={<FiligranIcon icon={LogoXtmOneIcon} size="small" color="ai" />}
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
  if (isEnterpriseEdition && !fullyActive) {
    return (
      <>
        <Tooltip title={t_i18n('AI Insights')}>
          {onlyIcon ? (
            <IconButton
              size="small"
              onClick={() => setDisplayAIDialog(true)}
              className={floating ? classes.chipFloating : classes.chip}
            >
              <FiligranIcon icon={LogoXtmOneIcon} size="small" color="ai" />
            </IconButton>
          ) : (
            <Button
              variant="secondary"
              size="small"
              onClick={() => setDisplayAIDialog(true)}
              className={floating ? classes.chipFloating : classes.chip}
              startIcon={<FiligranIcon icon={LogoXtmOneIcon} size="small" color="ai" />}
            >
              {t_i18n('AI Insights')}
            </Button>
          )}
        </Tooltip>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={displayAIDialog}
          onClose={() => setDisplayAIDialog(false)}
          fullWidth={true}
          maxWidth="sm"
        >
          <DialogTitle>
            {t_i18n('Enable AI powered platform')}
          </DialogTitle>
          <DialogContent>
            {t_i18n('To use this AI feature in the enterprise edition, please add a token.')}
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
            onClick={() => setDisplay(true)}
            className={floating ? classes.chipFloating : classes.chip}
          >
            <FiligranIcon icon={LogoXtmOneIcon} size="small" color="ai" />
          </IconButton>
        ) : (
          <Button
            variant="secondary"
            size="small"
            onClick={() => setDisplay(true)}
            className={floating ? classes.chipFloating : classes.chip}
            startIcon={<FiligranIcon icon={LogoXtmOneIcon} size="small" color="ai" />}
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
        onClose={handleClose}
        onClick={(e) => e.stopPropagation()}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            onClick={handleClose}
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="subtitle2" style={{ textWrap: 'nowrap' }}>
            {t_i18n('AI Insights')}
          </Typography>
          <Button
            variant="secondary"
            size="small"
            className={classes.chipNoAction}
            startIcon={<FiligranIcon icon={LogoXtmOneIcon} size="small" color="ai" />}
          >
            {t_i18n('XTM AI')}
          </Button>
        </div>
        <div className={classes.container}>
          <Box sx={{
            borderBottom: 1,
            borderColor: 'divider',
            display: 'flex',
            justifyContent: 'space-between',
            alignItem: 'center',
          }}
          >
            <Tabs value={currentTab} onChange={handleChangeTab}>
              {tabs.includes('activity') && <Tab value="activity" label={t_i18n('Activity')} />}
              {tabs.includes('containers') && <Tab value="containers" label={isContainer ? t_i18n('Container summary') : t_i18n('Containers digest')} />}
              {tabs.includes('forecast') && <Tab value="forecast" label={t_i18n('Forecast')} />}
              {tabs.includes('history') && <Tab value="history" label={t_i18n('Internal history')} />}
            </Tabs>
            {loading && (
              <div style={{ paddingTop: 10 }}>
                <Loader variant={LoaderVariant.inline} />
              </div>
            )}
          </Box>
          {currentTab === 'activity' && (
            <AISummaryActivity
              id={id}
              loading={loading}
              setLoading={setLoading}
            />
          )}
          {currentTab === 'containers' && (
            <AISummaryContainers
              busId={containersBusId}
              isContainer={isContainer}
              filters={containersFilters}
              helpers={containersFiltersHelpers}
              loading={loading}
              setLoading={setLoading}
            />
          )}
          {currentTab === 'forecast' && (
            <AISummaryForecast
              id={id}
              loading={loading}
              setLoading={setLoading}
            />
          )}
          {currentTab === 'history' && (
            <AISummaryHistory
              id={id}
              loading={loading}
              setLoading={setLoading}
            />
          )}
        </div>
      </Drawer>
    </>
  );
};

export default AIInsights;
