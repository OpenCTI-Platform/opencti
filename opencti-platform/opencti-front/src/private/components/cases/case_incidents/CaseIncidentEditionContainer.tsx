import { Close } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import { Theme } from '../../../../components/Theme';

import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { CaseIncidentEditionContainerCaseQuery } from './__generated__/CaseIncidentEditionContainerCaseQuery.graphql';
import CaseIncidentEditionOverview from './CaseIncidentEditionOverview';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
}));

interface CaseIncidentEditionContainerProps {
  queryRef: PreloadedQuery<CaseIncidentEditionContainerCaseQuery>;
  handleClose: () => void;
}

export const caseIncidentEditionQuery = graphql`
  query CaseIncidentEditionContainerCaseQuery($id: String!) {
    caseIncident(id: $id) {
      ...CaseIncidentEditionOverview_case
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CaseIncidentEditionContainer: FunctionComponent<
CaseIncidentEditionContainerProps
> = ({ queryRef, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const queryData = usePreloadedQuery(caseIncidentEditionQuery, queryRef);
  if (queryData.caseIncident === null) {
    return <ErrorNotFound />;
  }
  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Update an incident response')}
        </Typography>
        <SubscriptionAvatars context={queryData.caseIncident.editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <CaseIncidentEditionOverview
          caseRef={queryData.caseIncident}
          context={queryData.caseIncident.editContext}
          enableReferences={useIsEnforceReference('Case-Incident')}
          handleClose={handleClose}
        />
      </div>
    </div>
  );
};

export default CaseIncidentEditionContainer;
