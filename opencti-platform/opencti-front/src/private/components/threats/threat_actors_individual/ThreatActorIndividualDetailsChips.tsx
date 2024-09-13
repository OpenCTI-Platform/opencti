import { Button, Typography } from '@mui/material';
import React, { FunctionComponent, useEffect, useState } from 'react';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import AddPersonaThreatActorIndividual from './AddPersonasThreatActorIndividual';
import AddIndividualsThreatActorIndividual from './AddIndividualsThreatActorIndividual';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

type SupportedTypes = 'known-as' | 'impersonates';
type SupportedFields = 'persona_name' | 'name';

interface MappingFields {
  title: string,
  field: SupportedFields,
  path: string,
  AddComponent: React.FunctionComponent<{ threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data }>,
}

const typeMappings: Record<SupportedTypes, MappingFields> = {
  'known-as': {
    title: 'Also known as',
    field: 'persona_name',
    path: '/dashboard/observations/observables',
    AddComponent: AddPersonaThreatActorIndividual,
  },
  impersonates: {
    title: 'Impersonates',
    field: 'name',
    path: '/dashboard/entities/individuals',
    AddComponent: AddIndividualsThreatActorIndividual,
  },
};

interface ThreatActorIndividualDetailsChipsProps {
  data: ThreatActorIndividualDetails_ThreatActorIndividual$data,
  relType: SupportedTypes,
}

const ThreatActorIndividualDetailsChips: FunctionComponent<
ThreatActorIndividualDetailsChipsProps
> = ({
  data,
  relType,
}) => {
  const { title, field, path, AddComponent } = typeMappings[relType];

  const getRelationshipsOfType = (rel_type: SupportedTypes) => {
    const relations = [];
    for (const { node } of data.stixCoreRelationships?.edges ?? []) {
      const { relationship_type } = node ?? {};
      if (relationship_type === rel_type) relations.push(node);
    }
    return relations;
  };

  const [nodes, setNodes] = useState(getRelationshipsOfType(relType));

  useEffect(() => {
    setNodes(getRelationshipsOfType(relType));
  }, [data]);

  return (
    <div style={{ marginBottom: '20px' }}>
      <div style={{
        display: 'flex',
        flexDirection: 'row',
      }}
      >

        <Typography
          variant="h3"
          gutterBottom={true}
        >
          {title}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
          <AddComponent threatActorIndividual={data} />
        </Security>
      </div>
      <div className='clearfix' />
      <FieldOrEmpty source={nodes}>
        {
        nodes.map(({ id, to }) => (
          <Button
            key={id}
            variant='outlined'
            size='small'
            href={`${path}/${to?.id}`}
            style={{ margin: '0 5px 5px 0' }}
          >
            {to?.[field]}
          </Button>
        ))
      }
      </FieldOrEmpty>
    </div>
  );
};

export default ThreatActorIndividualDetailsChips;
