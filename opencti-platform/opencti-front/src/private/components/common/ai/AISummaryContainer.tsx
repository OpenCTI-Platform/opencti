import makeStyles from '@mui/styles/makeStyles';
import React, { ReactNode, useState } from 'react';
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
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';
import useAI from '../../../../utils/hooks/useAI';
import { fileUri } from '../../../../relay/environment';
import obasDark from '../../../../static/images/xtm/obas_dark.png';
import obasLight from '../../../../static/images/xtm/obas_light.png';

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

interface AiSummaryContainerProps {
  title: string
  children: ReactNode
  floating?: boolean
}

const AISummaryContainer = ({ title, children, floating = false }: AiSummaryContainerProps) => {
  const theme = useTheme<Theme>();
  const { bannerSettings: { bannerHeightNumber }, settings: { id: settingsId } } = useAuth();
  const classes = useStyles({ bannerHeightNumber });
  const isEnterpriseEdition = useEnterpriseEdition();
  const { fullyActive } = useAI();
  const { t_i18n } = useFormatter();
  const [display, setDisplay] = useState(false);
  const [displayEEDialog, setDisplayEEDialog] = useState(false);
  const [displayAIDialog, setDisplayAIDialog] = useState(false);
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  if (!isEnterpriseEdition) {
    return (
      <>
        <Tooltip title={`${t_i18n('AI Summary')}`}>
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
            {t_i18n('AI Summary')}
          </Button>
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
        <Tooltip title={`${t_i18n('AI Summary')}`}>
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
            {t_i18n('AI Summary')}
          </Button>
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
      <Tooltip title={`${t_i18n('AI Summary')}`}>
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
          {t_i18n('AI Summary')}
        </Button>
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
            {title}
          </Typography>
          <Typography variant="caption" style={{
            display: 'flex',
            alignItems: 'center',
            textWrap: 'nowrap',
            position: 'absolute',
            right: 10,
          }}
          >
            {t_i18n('Powered by')}&nbsp;<a href='https://docs.opencti.io' target='_blank' rel='noreferrer'>XTM
              Copilot</a>
            <Chip label="beta" color="secondary" size="small"
              style={{ marginLeft: 10, borderRadius: 4, fontSize: 10 }}
            />
          </Typography>
        </div>
        <div className={classes.container}>
          {children}
        </div>
      </Drawer>
    </>
  );
};

export default AISummaryContainer;
