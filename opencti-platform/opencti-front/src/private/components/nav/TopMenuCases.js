import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { FeedbackOutlined } from '@mui/icons-material';
import { makeStyles } from '@mui/styles';
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

const TopMenuCases = () => {
  const { t } = useFormatter();
  const location = useLocation();
  const classes = useStyles();
  return (
      <div>
        <Button component={Link}
          to="/dashboard/cases/feedbacks"
          variant={location.pathname === '/dashboard/cases/feedbacks' ? 'contained' : 'text'}
          size="small"
          color={location.pathname === '/dashboard/cases/feedbacks' ? 'secondary' : 'primary'}
          classes={{ root: classes.button }}>
          <FeedbackOutlined className={classes.icon} fontSize="small" />
          {t('Feedbacks')}
        </Button>
      </div>
  );
};

export default TopMenuCases;
