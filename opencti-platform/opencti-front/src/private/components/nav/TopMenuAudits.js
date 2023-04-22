import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';

const useStyles = makeStyles((theme) => ({
  button: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
}));

const TopMenuAudits = () => {
  const { t } = useFormatter();
  const location = useLocation();
  const classes = useStyles();

  return (
        <div>
            <Button component={Link} size="small" to="/dashboard/audits"
                    variant={location.pathname === '/dashboard/audits' || location.pathname === '/dashboard/audits' ? 'contained' : 'text'}
                    color={location.pathname === '/dashboard/audits' || location.pathname === '/dashboard/audits' ? 'secondary' : 'primary'}
                    classes={{ root: classes.button }}>
                {t('Audit')}
            </Button>
        </div>
  );
};

export default TopMenuAudits;
