import React, { FunctionComponent, useState } from 'react';
import { ThreatActorIndividual_ThreatActorIndividual$data } from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import CountryCreation from '@components/locations/countries/CountryCreation';
import { useLazyLoadQuery } from 'react-relay';
import AddThreatActorIndividualDemographicLines, {
  addIndividualsThreatActorIndividualLinesQuery,
} from '@components/threats/threat_actors_individual/AddThreatActorIndividualDemographicLines';
import { AddThreatActorIndividualDemographicLinesQuery } from '@components/threats/threat_actors_individual/__generated__/AddThreatActorIndividualDemographicLinesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';

interface AddThreatActorIndividualDemographicProps {
  threatActorIndividual: ThreatActorIndividual_ThreatActorIndividual$data,
  relType: string,
}

const AddThreatActorIndividualDemographic: FunctionComponent<
AddThreatActorIndividualDemographicProps
> = ({
  threatActorIndividual,
  relType,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [search, setSearch] = useState<string>('');
  const paginationOptions = { search };

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const handleSearch = (term: string) => setSearch(term);

  const data = useLazyLoadQuery<AddThreatActorIndividualDemographicLinesQuery>(
    addIndividualsThreatActorIndividualLinesQuery,
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
      title={t_i18n('Add country')}
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
          <CountryCreation
            paginationOptions={{
              search,
              count: 50,
            }}
          />
        </div>
      }
    >
      <AddThreatActorIndividualDemographicLines
        threatActorIndividual={threatActorIndividual}
        fragmentKey={data}
        relType={relType}
      />
    </Drawer>
  </div>);
};

export default AddThreatActorIndividualDemographic;
