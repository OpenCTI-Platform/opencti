import Drawer from '@components/common/drawer/Drawer';
import { Add } from '@mui/icons-material';
import { IconButton } from '@mui/material';
import React, { useState } from 'react';
import SearchInput from 'src/components/SearchInput';
import { useFormatter } from 'src/components/i18n';
import { useLazyLoadQuery } from 'react-relay';
import AddIndividualsThreatActorIndividualLines, { addIndividualsThreatActorIndividualLinesQuery } from './AddIndividualsThreatActorIndividualLines';
import { AddIndividualsThreatActorIndividualLinesQuery } from './__generated__/AddIndividualsThreatActorIndividualLinesQuery.graphql';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';

const AddIndividualsThreatActorIndividual = ({
  threatActorIndividual,
}: {
  threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [search, setSearch] = useState<string>('');
  const paginationOptions = { search };

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const handleSearch = (term: string) => setSearch(term);

  const data = useLazyLoadQuery<AddIndividualsThreatActorIndividualLinesQuery>(
    addIndividualsThreatActorIndividualLinesQuery,
    {
      ...paginationOptions,
      count: 50,
    },
  );
  const getRelationships = () => {
    const relations = [];
    for (const { node } of threatActorIndividual.stixCoreRelationships?.edges ?? []) {
      const { relationship_type } = node ?? {};
      if (relationship_type === 'impersonates') relations.push(node);
    }
    return relations;
  };

  return (<div>
    {(getRelationships().length > 0) && (
      <IconButton
        color='primary'
        style={{ marginTop: '-11px' }}
        onClick={handleOpen}
      >
        <Add fontSize="small" />
      </IconButton>
    )}
    <Drawer
      open={open}
      onClose={handleClose}
      title={t_i18n('Add individual')}
      header={
        <div
          style={{
            marginLeft: 'auto',
            marginRight: '20px',
          }}
        >
          <SearchInput
            variant='inDrawer'
            onSubmit={handleSearch}
          />
        </div>
      }
    >
      <AddIndividualsThreatActorIndividualLines
        threatActorIndividual={threatActorIndividual}
        fragmentKey={data}
      />
    </Drawer>
  </div>);
};

export default AddIndividualsThreatActorIndividual;
