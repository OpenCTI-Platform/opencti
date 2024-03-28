import React from 'react';
import { useMutation } from 'react-relay';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
import { useFormatter } from 'src/components/i18n';
import { makeStyles } from '@mui/styles';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ThreatActorIndividualEditionContainer, { ThreatActorIndividualEditionQuery } from './ThreatActorIndividualEditionContainer';
import { ThreatActorIndividualEditionOverviewFocusMutation } from './__generated__/ThreatActorIndividualEditionOverviewFocusMutation.graphql';
import { ThreatActorIndividualEditionContainerQuery } from './__generated__/ThreatActorIndividualEditionContainerQuery.graphql';
import { ThreatActorIndividualEditionOverviewFocus } from './ThreatActorIndividualEditionOverview';

const useStyles = makeStyles(() => ({
  actionBtns: {
    marginLeft: '3px',
    fontSize: 'small',
  },
}));

const ThreatActorIndividualEdition = ({
  threatActorIndividualId,
}: {
  threatActorIndividualId: string;
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [commit] = useMutation<ThreatActorIndividualEditionOverviewFocusMutation>(
    ThreatActorIndividualEditionOverviewFocus,
  );
  const handleClose = () => {
    commit({
      variables: {
        id: threatActorIndividualId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<ThreatActorIndividualEditionContainerQuery>(
    ThreatActorIndividualEditionQuery,
    { id: threatActorIndividualId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ThreatActorIndividualEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={({ onOpen }) => (
              <Button
                className={classes.actionBtns}
                variant='outlined'
                onClick={onOpen}
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

export default ThreatActorIndividualEdition;
