import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import { Theme } from '../../../../components/Theme';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import DataSourceEditionOverview from './DataSourceEditionOverview';
import { DataSourceEditionContainerQuery } from './__generated__/DataSourceEditionContainerQuery.graphql';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

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

export const dataSourceEditionQuery = graphql`
  query DataSourceEditionContainerQuery($id: String!) {
    dataSource(id: $id) {
      ...DataSourceEditionOverview_dataSource
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface DataSourceEditionContainerProps {
  handleClose: () => void;
  queryRef: PreloadedQuery<DataSourceEditionContainerQuery>;
}

const DataSourceEditionContainer: FunctionComponent<
DataSourceEditionContainerProps
> = ({ handleClose, queryRef }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const queryData = usePreloadedQuery(dataSourceEditionQuery, queryRef);

  if (queryData.dataSource) {
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
            {t('Update a data source')}
          </Typography>
          <SubscriptionAvatars context={queryData.dataSource.editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <DataSourceEditionOverview
            data={queryData.dataSource}
            enableReferences={useIsEnforceReference('Data-Source')}
            context={queryData.dataSource.editContext}
            handleClose={handleClose}
          />
        </div>
      </div>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default DataSourceEditionContainer;
