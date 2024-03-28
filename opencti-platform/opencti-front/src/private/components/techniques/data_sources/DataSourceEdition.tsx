import React from 'react';
import { useMutation } from 'react-relay';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
import { useFormatter } from 'src/components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { dataSourceEditionOverviewFocus } from './DataSourceEditionOverview';
import DataSourceEditionContainer, { dataSourceEditionQuery } from './DataSourceEditionContainer';
import { DataSourceEditionContainerQuery } from './__generated__/DataSourceEditionContainerQuery.graphql';

const DataSourceEdition = ({ dataSourceId }: { dataSourceId: string }) => {
  const { t_i18n } = useFormatter();
  const [commit] = useMutation(dataSourceEditionOverviewFocus);

  const handleClose = () => {
    commit({
      variables: {
        id: dataSourceId,
        input: { focusOn: '' },
      },
    });
  };

  const queryRef = useQueryLoading<DataSourceEditionContainerQuery>(
    dataSourceEditionQuery,
    { id: dataSourceId },
  );

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <DataSourceEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={({ onOpen }) => (
              <Button
                style={{
                  marginLeft: '3px',
                  fontSize: 'small',
                }}
                variant='contained'
                onClick={onOpen}
                disableElevation
              >
                {t_i18n('Edit')} <Create />
              </Button>
            )}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default DataSourceEdition;
