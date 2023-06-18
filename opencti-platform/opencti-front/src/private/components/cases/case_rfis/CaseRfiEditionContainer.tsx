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
import { CaseRfiEditionContainerCaseQuery } from './__generated__/CaseRfiEditionContainerCaseQuery.graphql';
import CaseRfiEditionOverview from './CaseRfiEditionOverview';

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

interface CaseRfiEditionContainerProps {
  queryRef: PreloadedQuery<CaseRfiEditionContainerCaseQuery>
  handleClose: () => void
}

export const caseRfiEditionQuery = graphql`
  query CaseRfiEditionContainerCaseQuery($id: String!) {
    caseRfi(id: $id) {
      ...CaseRfiEditionOverview_case
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CaseRfiEditionContainer: FunctionComponent<
CaseRfiEditionContainerProps
> = ({ queryRef, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const queryData = usePreloadedQuery(caseRfiEditionQuery, queryRef);
  if (queryData.caseRfi === null) {
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
          {t('Update a request for information')}
        </Typography>
        <SubscriptionAvatars context={queryData.caseRfi.editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <CaseRfiEditionOverview
          caseRef={queryData.caseRfi}
          context={queryData.caseRfi.editContext}
          enableReferences={useIsEnforceReference('Case-Rfi')}
          handleClose={handleClose}
        />
      </div>
    </div>
  );
};

export default CaseRfiEditionContainer;
