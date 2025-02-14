import Drawer from '@components/common/drawer/Drawer';
import { Add } from '@mui/icons-material';
import { IconButton } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import SearchInput from 'src/components/SearchInput';
import { useFormatter } from 'src/components/i18n';
import AddPersonasThreatActorIndividualLines, { addPersonasThreatActorIndividualLinesQuery } from './AddPersonasThreatActorIndividualLines';
import {
  AddPersonasThreatActorIndividualLinesQuery,
  AddPersonasThreatActorIndividualLinesQuery$variables,
} from './__generated__/AddPersonasThreatActorIndividualLinesQuery.graphql';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface AddPersonaThreatActorIndividualComponentProps {
  threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data,
  queryRef: PreloadedQuery<AddPersonasThreatActorIndividualLinesQuery>,
  onSearch: (search: string) => void,
  paginationOptions: AddPersonasThreatActorIndividualLinesQuery$variables,
}

const AddPersonaThreatActorIndividualComponent: FunctionComponent<
AddPersonaThreatActorIndividualComponentProps
> = ({
  threatActorIndividual,
  queryRef,
  onSearch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

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
            onSubmit={onSearch}
          />
          <div style={{ height: 5 }} />
          <StixCyberObservableCreation
            contextual={false}
            type="Persona"
            paginationOptions={paginationOptions}
            paginationKey="Pagination_tai_stixCyberObservables"
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

interface AddPersonaThreatActorIndividualProps {
  threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data,
}

const AddPersonaThreatActorIndividual: FunctionComponent<AddPersonaThreatActorIndividualProps> = (props) => {
  const [paginationOptions, setPaginationOptions] = useState({ count: 50, search: '', types: ['Persona'] });
  const queryRef = useQueryLoading<AddPersonasThreatActorIndividualLinesQuery>(
    addPersonasThreatActorIndividualLinesQuery,
    paginationOptions,
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <AddPersonaThreatActorIndividualComponent
        {...props}
        queryRef={queryRef}
        onSearch={(search) => setPaginationOptions({ count: 50, search, types: ['Persona'] })}
        paginationOptions={paginationOptions}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default AddPersonaThreatActorIndividual;
