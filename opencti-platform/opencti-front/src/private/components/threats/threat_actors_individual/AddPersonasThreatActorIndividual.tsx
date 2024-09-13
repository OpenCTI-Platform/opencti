import Drawer from '@components/common/drawer/Drawer';
import { Add } from '@mui/icons-material';
import { IconButton } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { useLazyLoadQuery } from 'react-relay';
import SearchInput from 'src/components/SearchInput';
import { useFormatter } from 'src/components/i18n';
import AddPersonasThreatActorIndividualLines, { addPersonasThreatActorIndividualLinesQuery } from './AddPersonasThreatActorIndividualLines';
import { AddPersonasThreatActorIndividualLinesQuery } from './__generated__/AddPersonasThreatActorIndividualLinesQuery.graphql';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';

interface AddPersonaThreatActorIndividualProps {
  threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data,
}

const AddPersonaThreatActorIndividual: FunctionComponent<
AddPersonaThreatActorIndividualProps
> = ({
  threatActorIndividual,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [search, setSearch] = useState<string>('');
  const paginationOptions = { search };

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const handleSearch = (term: string) => setSearch(term);

  const data = useLazyLoadQuery<AddPersonasThreatActorIndividualLinesQuery>(
    addPersonasThreatActorIndividualLinesQuery,
    {
      ...paginationOptions,
      count: 50,
    },
  );

  return (<div>
    <IconButton
      color='primary'
      style={{ marginTop: '-11px' }}
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
            open={undefined}
            handleClose={undefined}
            onCompleted={undefined}
            display={undefined}
            speeddial={undefined}
            isFromBulkRelation={undefined}
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

export default AddPersonaThreatActorIndividual;
