import React, { FunctionComponent } from 'react';
import { useMutation } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CaseRftEditionContainerCaseQuery } from './__generated__/CaseRftEditionContainerCaseQuery.graphql';
import CaseRftEditionContainer, { caseRftEditionQuery } from './CaseRftEditionContainer';
import { caseRftEditionOverviewFocus } from './CaseRftEditionOverview';

const CaseRftEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const { t_i18n } = useFormatter();
  const [commit] = useMutation(caseRftEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: caseId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<CaseRftEditionContainerCaseQuery>(
    caseRftEditionQuery,
    { id: caseId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <CaseRftEditionContainer
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

export default CaseRftEdition;
