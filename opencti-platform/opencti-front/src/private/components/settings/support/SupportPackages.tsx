import React from 'react';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import {
  SupportPackageLinesPaginationQuery,
  SupportPackageLinesPaginationQuery$variables,
} from '@components/settings/support/__generated__/SupportPackageLinesPaginationQuery.graphql';
import SupportPackageLines, { supportPackageLinesQuery } from '@components/settings/support/SupportPackageLines';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { handleError, MESSAGING$ } from '../../../../relay/environment';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ListLines from '../../../../components/list_lines/ListLines';
import { insertNode } from '../../../../utils/store';
import { SETTINGS_SUPPORT } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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
  const [commitSupportPackageAdd] = useApiMutation(supportPackageAddMutation);
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<SupportPackageLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'created_at',
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
      onError: (error: Error) => {
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
        width: '45%',
        isSortable: true,
      },
      package_status: {
        label: 'Status',
        width: '20%',
        isSortable: false,
      },
      created_at: {
        label: 'Date',
        width: '15%',
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
        handleSort={helpers.handleSort}
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
    <Security needs={[SETTINGS_SUPPORT]} placeholder={<>{t_i18n('You do not have any access to the knowledge of this OpenCTI instance.')}</>}>
      <div>
        <Breadcrumbs variant="list"
          elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Support packages'), current: true }]}
        />
        <Grid container={true} spacing={4}>
          <Grid item={true} xs={12} style={{ paddingTop: '24px' }}>
            <div>
              <Typography variant="h4" gutterBottom={true} style={{ marginBottom: '10px' }}>
                {t_i18n('Generated Support Package')}
              </Typography>
              <Button
                style={{ float: 'right', marginTop: '-40px' }}
                onClick={generateSupportPackage}
                size="small"
                variant="outlined"
                color="primary"
              >
                {t_i18n('Generate Support Package')}
              </Button>
              <div className="clearfix"/>
              <Alert
                severity="warning"
                variant="outlined"
                style={{ position: 'relative', marginTop: 20, marginBottom: 20 }}
              >
                {t_i18n('Even if we do our best to prevent logging any data, the support package may contains some sensitive information that you may not want to share with everyone.')}<br/>
                {t_i18n('Before creating a ticket with your support package takes some time to check if you can safely share the content depending of your security policy.')}
              </Alert>
              <Paper variant="outlined" style={{
                height: '100%',
                minHeight: '100%',
                padding: '10px 15px 10px 15px',
                borderRadius: 4,
              }}
              >
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
