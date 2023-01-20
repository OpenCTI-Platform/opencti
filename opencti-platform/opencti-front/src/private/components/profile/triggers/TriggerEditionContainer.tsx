import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { TriggerEditionContainerQuery } from './__generated__/TriggerEditionContainerQuery.graphql';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import TriggerEditionOverview from './TriggerEditionOverview';

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

export const triggerEditionQuery = graphql`
  query TriggerEditionContainerQuery($id: String!) {
    trigger(id: $id) {
      ...TriggerEditionOverview_trigger
    }
  }
`;

interface TriggerEditionContainerProps {
  handleClose: () => void;
  queryRef: PreloadedQuery<TriggerEditionContainerQuery>;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
}

const TriggerEditionContainer: FunctionComponent<
TriggerEditionContainerProps
> = ({ handleClose, queryRef, paginationOptions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const queryData = usePreloadedQuery(triggerEditionQuery, queryRef);
  if (queryData.trigger) {
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
            {t('Update a trigger')}
          </Typography>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <TriggerEditionOverview
            data={queryData.trigger}
            handleClose={handleClose}
            paginationOptions={paginationOptions}
          />
        </div>
      </div>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default TriggerEditionContainer;
