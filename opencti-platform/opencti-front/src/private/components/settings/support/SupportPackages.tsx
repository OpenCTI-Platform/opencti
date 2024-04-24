import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Button from '@mui/material/Button';
import { graphql, useMutation } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import {
  SupportPackageLinesPaginationQuery,
  SupportPackageLinesPaginationQuery$variables,
} from '@components/settings/support/__generated__/SupportPackageLinesPaginationQuery.graphql';
import SupportPackageLines, { supportPackageLinesQuery } from '@components/settings/support/SupportPackageLines';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import type { Theme } from '../../../../components/Theme';
import { handleError, MESSAGING$ } from '../../../../relay/environment';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ListLines from '../../../../components/list_lines/ListLines';
import { insertNode } from '../../../../utils/store';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

const useStyles = makeStyles<Theme>(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: '10px 15px 10px 15px',
    marginTop: -2,
    borderRadius: 4,
  },
  gridContainer: {
    marginBottom: 20,
    marginTop: 20,
    minHeight: '250px',
  },
  createButton: {
    float: 'right',
  },
}));

const LOCAL_STORAGE_KEY = 'support-packages';

export const supportPackageAddMutation = graphql`
  mutation SupportPackagesMutation(
    $input: SupportPackageAddInput!
  ) {
    supportPackageAdd(input: $input) {
      id
      name
      package_url
      package_status
    }
  }
`;

const SupportPackages = () => {
  const { t_i18n, nsdt } = useFormatter();
  const classes = useStyles();
  const [commitSupportPackageAdd] = useMutation(supportPackageAddMutation);
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<SupportPackageLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: '',
      orderAsc: false,
    },
  );

  const generateSupportPackage = () => {
    const supportPackageName = `support-package-${nsdt(new Date())}`;
    commitSupportPackageAdd({
      variables: {
        input: {
          name: supportPackageName,
        },
      },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_supportPackages',
          paginationOptions,
          'supportPackageAdd',
        );
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(
          `Support package request send for ${supportPackageName}.`,
        );
      },
      onError: (error) => {
        handleError(error);
      },
    });
  };

  const renderLines = () => {
    const { sortBy, orderAsc, searchTerm } = viewStorage;
    const queryRef = useQueryLoading<SupportPackageLinesPaginationQuery>(
      supportPackageLinesQuery,
      paginationOptions,
    );
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
      },
      packageStatus: {
        label: 'Status',
        width: '25%',
        isSortable: true,
      },
      creators: {
        label: 'Creator',
        width: '25%',
        isSortable: true,
      },
      created: {
        label: 'Date',
        width: '25%',
        isSortable: true,
      },
    };
    return (
      <ListLines
        helpers={helpers}
        dataColumns={dataColumns}
        sortBy={sortBy}
        orderAsc={orderAsc}
        keyword={searchTerm}
      >
        {queryRef && (
          <React.Suspense>
            <SupportPackageLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              setNumberOfElements={helpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };

  return (
    <Security
      needs={[KNOWLEDGE]}
      placeholder={<>{t_i18n(
        'You do not have any access to the knowledge of this OpenCTI instance.',
      )}</>}
    >
      <div className={classes.container}>
        <Breadcrumbs variant="list"
          elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Support packages'), current: true }]}
        />

        <Grid container={true} spacing={4}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={8} style={{ paddingTop: 10 }}>
            <div style={{ height: '100%' }}>
              <div className="clearfix"/>
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <Typography variant="h4" gutterBottom={true} style={{ float: 'left', marginTop: '8px', fontSize: '13px', marginBottom: '40px' }}>
                  {t_i18n('Generated Support Package')}
                </Typography>
                <Button
                  classes={{ root: classes.createButton }}
                  onClick={generateSupportPackage}
                  size="small"
                  variant="outlined"
                  color="primary"
                >
                  {t_i18n('Generate Support Package')}
                </Button>
                {renderLines()}
              </Paper>
            </div>
          </Grid>
        </Grid>
      </div>
    </Security>
  );
};

export default SupportPackages;
