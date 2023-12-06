import React, { FunctionComponent } from 'react';
import { useMutation } from 'react-relay';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
import { useFormatter } from 'src/components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CaseIncidentEditionContainerCaseQuery } from './__generated__/CaseIncidentEditionContainerCaseQuery.graphql';
import CaseIncidentEditionContainer, { caseIncidentEditionQuery } from './CaseIncidentEditionContainer';
import { caseIncidentEditionOverviewFocus } from './CaseIncidentEditionOverview';

const CaseIncidentEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const { t_i18n } = useFormatter();
  const [commit] = useMutation(caseIncidentEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: caseId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<CaseIncidentEditionContainerCaseQuery>(
    caseIncidentEditionQuery,
    { id: caseId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <CaseIncidentEditionContainer
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

export default CaseIncidentEdition;
