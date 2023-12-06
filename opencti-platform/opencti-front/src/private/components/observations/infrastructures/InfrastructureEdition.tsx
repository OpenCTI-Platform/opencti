import React from 'react';
import { useMutation } from 'react-relay';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
import { useFormatter } from 'src/components/i18n';
import InfrastructureEditionContainer, { infrastructureEditionContainerQuery } from './InfrastructureEditionContainer';
import { infrastructureEditionOverviewFocus } from './InfrastructureEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { InfrastructureEditionContainerQuery } from './__generated__/InfrastructureEditionContainerQuery.graphql';

const InfrastructureEdition = ({ infrastructureId }: { infrastructureId: string }) => {
  const { t_i18n } = useFormatter();
  const [commit] = useMutation(infrastructureEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: infrastructureId,
        input: { focusOn: '' },
      },
    });
  };

  const queryRef = useQueryLoading<InfrastructureEditionContainerQuery>(
    infrastructureEditionContainerQuery,
    { id: infrastructureId },
  );

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <InfrastructureEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={({ onOpen }) => (
              <Button
                onClick={onOpen}
                variant='outlined'
                style={{
                  marginLeft: '3px',
                  fontSize: 'small',
                }}
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

export default InfrastructureEdition;
