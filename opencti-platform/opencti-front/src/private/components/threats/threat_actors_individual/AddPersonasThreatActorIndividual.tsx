import Drawer from '@components/common/drawer/Drawer';
import { Add } from '@mui/icons-material';
import { IconButton } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import SearchInput from 'src/components/SearchInput';
import { useFormatter } from 'src/components/i18n';
import AddPersonasThreatActorIndividualLines, { addPersonasThreatActorIndividualLinesQuery } from './AddPersonasThreatActorIndividualLines';
import { AddPersonasThreatActorIndividualLinesQuery } from './__generated__/AddPersonasThreatActorIndividualLinesQuery.graphql';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface AddPersonaThreatActorIndividualComponentProps {
  threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data,
  queryRef: PreloadedQuery<AddPersonasThreatActorIndividualLinesQuery>,
}

const AddPersonaThreatActorIndividualComponent: FunctionComponent<
AddPersonaThreatActorIndividualComponentProps
> = ({
  threatActorIndividual,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [search, setSearch] = useState<string>('');

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const handleSearch = (term: string) => setSearch(term);

  const data = usePreloadedQuery<AddPersonasThreatActorIndividualLinesQuery>(
    addPersonasThreatActorIndividualLinesQuery,
    queryRef,
  );

  return (<div>
    <IconButton
      color='primary'
      onClick={handleOpen}
    >
      <Add fontSize="small" />
    </IconButton>
    <Drawer
      open={open}
      onClose={handleClose}
      title={t_i18n('Add persona')}
      header={
        <div
          style={{
            marginLeft: 'auto',
            marginRight: '20px',
            display: 'flex',
            flexWrap: 'wrap',
            justifyContent: 'flex-end',
            alignItems: 'flex-end',
          }}
        >
          <SearchInput
            variant='inDrawer'
            onSubmit={handleSearch}
          />
          <div style={{ height: 5 }} />
          <StixCyberObservableCreation
            contextual={false}
            type="Persona"
            inputValue={search}
            paginationOptions={{ search, types: ['Persona'] }}
            paginationKey="Pagination_stixCyberObservables"
            controlledDialStyles={{
              marginLeft: '10px',
              marginTop: '5px',
            }}
          />
        </div>
      }
    >
      <AddPersonasThreatActorIndividualLines
        threatActorIndividual={threatActorIndividual}
        fragmentKey={data}
      />
    </Drawer>
  </div>);
};

const AddPersonaThreatActorIndividual: FunctionComponent<
Omit<AddPersonaThreatActorIndividualComponentProps, 'queryRef'>
> = (props) => {
  const queryRef = useQueryLoading<AddPersonasThreatActorIndividualLinesQuery>(addPersonasThreatActorIndividualLinesQuery, {
    count: 50,
  });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <AddPersonaThreatActorIndividualComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default AddPersonaThreatActorIndividual;
