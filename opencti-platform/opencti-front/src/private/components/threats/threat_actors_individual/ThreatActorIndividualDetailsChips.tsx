import Button from '@common/button/Button';
import React, { FunctionComponent, useEffect, useState } from 'react';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import AddPersonaThreatActorIndividual from './AddPersonasThreatActorIndividual';
import AddIndividualsThreatActorIndividual from './AddIndividualsThreatActorIndividual';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import CardLabel from '../../../../components/CardLabel';

type SupportedTypes = 'known-as' | 'impersonates';
type SupportedFields = 'observable_value' | 'name';

interface MappingFields {
  title: string;
  field: SupportedFields;
  path: string;
  AddComponent: React.FunctionComponent<{ threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data }>;
}

const typeMappings: Record<SupportedTypes, MappingFields> = {
  'known-as': {
    title: 'Also known as',
    field: 'observable_value',
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
  data: ThreatActorIndividualDetails_ThreatActorIndividual$data;
  relType: SupportedTypes;
}

const ThreatActorIndividualDetailsChips: FunctionComponent<
  ThreatActorIndividualDetailsChipsProps
> = ({
  data,
  relType,
}) => {
  const { title, field, path, AddComponent } = typeMappings[relType];

  const getRelationshipsOfType = (rel_type: SupportedTypes) => {
    const seen_persona_id_set = new Set<string>();
    const relations = [];
    for (const { node } of data.stixCoreRelationships?.edges ?? []) {
      const { relationship_type } = node ?? {};
      if (relationship_type === rel_type && node.to?.id !== undefined && !(seen_persona_id_set.has(node.to.id))) {
        relations.push(node);
        seen_persona_id_set.add(node.to.id);
      }
    }
    return relations;
  };

  const [nodes, setNodes] = useState(getRelationshipsOfType(relType));

  useEffect(() => {
    setNodes(getRelationshipsOfType(relType));
  }, [data]);

  return (
    <div style={{ marginBottom: '20px' }}>
      <CardLabel action={(
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
        >
          <AddComponent threatActorIndividual={data} />
        </Security>
      )}
      >
        {title}
      </CardLabel>
      <div className="clearfix" />
      <FieldOrEmpty source={nodes}>
        {
          nodes.map(({ id, to }) => (
            <Button
              key={id}
              variant="secondary"
              size="small"
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
