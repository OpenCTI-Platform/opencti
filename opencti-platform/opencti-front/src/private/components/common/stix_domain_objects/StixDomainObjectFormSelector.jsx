import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close, Assignment } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';

import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles((theme) => ({
  drawer: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 0px 20px 20px',
    display: 'flex',
    alignItems: 'center',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '20px',
  },
  loaderContainer: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    minHeight: 200,
  },
  emptyState: {
    margin: '20px',
  },
  listItem: {
    marginBottom: theme.spacing(1),
  },
}));

const formSelectorQuery = graphql`
  query StixDomainObjectFormSelectorQuery($filters: FilterGroup) {
    forms(filters: $filters, first: 50, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
          description
          active
          form_schema
        }
      }
    }
  }
`;

const StixDomainObjectFormSelector = ({ open, handleClose, entityType }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();

  const handleFormSelect = (formId) => {
    // Navigate to the form viewer
    navigate(`/dashboard/data/ingestion/forms/${formId}`);
    handleClose();
  };

  const renderContent = () => {
    try {
      // Fetch all forms and filter client-side based on parsed schema
      const data = useLazyLoadQuery(formSelectorQuery, { filters: null });

      if (!data?.forms?.edges || data.forms.edges.length === 0) {
        return (
          <Alert severity="info" className={classes.emptyState}>
            {t_i18n('No forms available')}
          </Alert>
        );
      }

      // Filter forms that match the entity type
      const relevantForms = data.forms.edges.filter(({ node }) => {
        if (!node.active) return false;

        try {
          const schema = JSON.parse(node.form_schema);
          // Match the entity type (case insensitive and handle different formats)
          const formEntityType = schema.mainEntityType || '';
          return formEntityType.toLowerCase() === entityType.toLowerCase()
                 || formEntityType.toLowerCase() === entityType.toLowerCase().replace(/-/g, '_');
        } catch {
          return false;
        }
      });

      if (relevantForms.length === 0) {
        return (
          <Alert severity="info" className={classes.emptyState}>
            {t_i18n('No forms available for this entity type')}
          </Alert>
        );
      }

      return (
        <List>
          {relevantForms.map(({ node }) => {
            return (
              <ListItem
                key={node.id}
                disablePadding
                className={classes.listItem}
              >
                <ListItemButton
                  onClick={() => handleFormSelect(node.id)}
                  sx={{
                    borderRadius: 1,
                    '&:hover': {
                      backgroundColor: 'rgba(0, 0, 0, 0.04)',
                    },
                  }}
                >
                  <ListItemIcon>
                    <Assignment color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={node.name}
                    secondary={node.description}
                  />
                </ListItemButton>
              </ListItem>
            );
          })}
        </List>
      );
    } catch (error) {
      return (
        <Alert severity="error" className={classes.emptyState}>
          {t_i18n('Error loading forms')}
        </Alert>
      );
    }
  };

  return (
    <Drawer
      open={open}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: classes.drawer }}
      onClose={handleClose}
    >
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" />
        </IconButton>
        <Typography variant="h6" sx={{ marginLeft: '40px' }}>
          {t_i18n('Select a form')}
        </Typography>
      </div>
      <div className={classes.container}>
        <React.Suspense
          fallback={
            <div className={classes.loaderContainer}>
              <CircularProgress />
            </div>
          }
        >
          {renderContent()}
        </React.Suspense>
      </div>
    </Drawer>
  );
};

export default StixDomainObjectFormSelector;
