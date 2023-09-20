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
import { CaseRftEditionContainerCaseQuery } from './__generated__/CaseRftEditionContainerCaseQuery.graphql';
import CaseRftEditionOverview from './CaseRftEditionOverview';

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
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
}));

interface CaseRftEditionContainerProps {
  queryRef: PreloadedQuery<CaseRftEditionContainerCaseQuery>;
  handleClose: () => void;
}

export const caseRftEditionQuery = graphql`
  query CaseRftEditionContainerCaseQuery($id: String!) {
    caseRft(id: $id) {
      ...CaseRftEditionOverview_case
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CaseRftEditionContainer: FunctionComponent<
CaseRftEditionContainerProps
> = ({ queryRef, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const queryData = usePreloadedQuery(caseRftEditionQuery, queryRef);
  if (queryData.caseRft === null) {
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
          {t('Update a request for takedown')}
        </Typography>
        <SubscriptionAvatars context={queryData.caseRft.editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <CaseRftEditionOverview
          caseRef={queryData.caseRft}
          context={queryData.caseRft.editContext}
          enableReferences={useIsEnforceReference('Case-Rft')}
          handleClose={handleClose}
        />
      </div>
    </div>
  );
};

export default CaseRftEditionContainer;
