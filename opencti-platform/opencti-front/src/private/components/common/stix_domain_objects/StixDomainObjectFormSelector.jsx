import React, { Suspense } from 'react';
import { graphql, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import List from '@mui/material/List';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress';
import { makeStyles } from '@mui/styles';
import { Assignment } from '@mui/icons-material';
import Drawer from '../drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  emptyState: {
    margin: '20px',
  },
  loaderContainer: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    minHeight: '200px',
  },
}));

const formSelectorQuery = graphql`
  query StixDomainObjectFormSelectorQuery {
    forms(first: 50, orderBy: name, orderMode: asc) {
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

// Component that uses the preloaded query
const FormSelectorContent = ({ queryRef, entityType, handleFormSelect }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const data = usePreloadedQuery(formSelectorQuery, queryRef);

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
      {relevantForms.map(({ node }) => (
        <ListItemButton
          key={node.id}
          onClick={() => handleFormSelect(node.id)}
          divider
        >
          <ListItemIcon>
            <Assignment color="primary" />
          </ListItemIcon>
          <ListItemText
            primary={node.name}
            secondary={node.description || null}
          />
        </ListItemButton>
      ))}
    </List>
  );
};

const StixDomainObjectFormSelectorInner = ({ queryRef, entityType, onClose }) => {
  const classes = useStyles();
  const navigate = useNavigate();

  const handleFormSelect = (formId) => {
    navigate(`/dashboard/data/ingestion/forms/${formId}`);
    onClose();
  };

  return (
    <Suspense
      fallback={
        <div className={classes.loaderContainer}>
          <CircularProgress />
        </div>
      }
    >
      <FormSelectorContent
        queryRef={queryRef}
        entityType={entityType}
        handleFormSelect={handleFormSelect}
      />
    </Suspense>
  );
};

const StixDomainObjectFormSelector = ({ open, handleClose, entityType }) => {
  const { t_i18n } = useFormatter();
  const [queryRef, loadQuery] = useQueryLoader(formSelectorQuery);

  React.useEffect(() => {
    if (open && !queryRef) {
      loadQuery({}, { fetchPolicy: 'store-and-network' });
    }
  }, [open, loadQuery, queryRef]);

  return (
    <Drawer
      open={open}
      onClose={handleClose}
      title={t_i18n('Select a form')}
      variant="slide"
    >
      {({ onClose }) => (
        queryRef ? (
          <React.Suspense
            fallback={
              <div style={{ display: 'flex', justifyContent: 'center', padding: '20px' }}>
                <CircularProgress />
              </div>
            }
          >
            <StixDomainObjectFormSelectorInner
              queryRef={queryRef}
              entityType={entityType}
              onClose={onClose}
            />
          </React.Suspense>
        ) : (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '20px' }}>
            <CircularProgress />
          </div>
        )
      )}
    </Drawer>
  );
};

export default StixDomainObjectFormSelector;
