import React from 'react';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import {
  SupportPackageLinesPaginationQuery,
  SupportPackageLinesPaginationQuery$variables,
} from '@components/settings/support/__generated__/SupportPackageLinesPaginationQuery.graphql';
import SupportPackageLines, { supportPackageLinesQuery } from '@components/settings/support/SupportPackageLines';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Alert from '@mui/material/Alert';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../../relay/environment';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ListLines from '../../../../components/list_lines/ListLines';
import { insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import Card from '../../../../components/common/card/Card';

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
  const draftContext = useDraftContext();
  const disabledInDraft = !!draftContext;
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
    <>
      <Card
        title={t_i18n('Support packages')}
        titleSx={{ alignItems: 'end' }}
        sx={{
          maxHeight: '600px',
          overflowY: 'auto',
        }}
        action={(
          <Tooltip title={(
            <Alert
              severity="warning"
              variant="outlined"
              style={{ position: 'relative', marginTop: 20, marginBottom: 20 }}
            >
              {disabledInDraft
                ? t_i18n('You cannot generate a support package while in draft mode. Make sure to be out of draft to generate one.')
                : t_i18n('We are doing our best to remove any sensitive information from support packages but we encourage you to check the content before sharing a support package depending on your security policy.')}
            </Alert>
          )}
          >
            <span style={{ float: 'right', marginTop: '-34px', display: 'inline-block' }}>
              <Button
                onClick={generateSupportPackage}
                size="small"
                variant="outlined"
                color="primary"
                disabled={disabledInDraft}
              >
                {t_i18n('Generate Support Package')}
              </Button>
            </span>
          </Tooltip>
        )}
      >
        {renderLines()}
      </Card>
    </>
  );
};

export default SupportPackages;
