import React, { FunctionComponent } from 'react';
import { stixDomainObjectMutation } from '@components/common/stix_domain_objects/StixDomainObjectHeader';
import Tooltip from '@mui/material/Tooltip';
import FieldOrEmpty from './FieldOrEmpty';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../utils/hooks/useGranted';
import { truncate } from '../utils/String';
import { commitMutation, defaultCommitMutation } from '../relay/environment';
import Tag from './common/tag/Tag';

interface ItemParticipantsProps {
  participants: {
    readonly entity_type: string;
    readonly id: string;
    readonly name: string;
  }[];
  stixDomainObjectId: string;
}

const ItemParticipants: FunctionComponent<ItemParticipantsProps> = ({ participants, stixDomainObjectId }) => {
  const canUpdateKnowledge = useGranted([KNOWLEDGE_KNUPDATE]);
  const handleRemoveParticipant = (removedId: string) => {
    const values = participants.filter((participant) => participant.id !== removedId);
    const valuesIds = values.map((value) => value.id);
    commitMutation({
      mutation: stixDomainObjectMutation,
      variables: {
        id: stixDomainObjectId,
        input: {
          key: 'objectParticipant',
          value: valuesIds,
        },
      },
      ...defaultCommitMutation,
    });
  };
  return (
    <FieldOrEmpty source={participants}>
      {participants.map((participant) => (
        <Tooltip key={participant.id} title={participant.name}>
          <Tag
            key={participant.id}
            label={truncate(participant.name, 25)}
            onDelete={canUpdateKnowledge ? () => (handleRemoveParticipant(participant.id)) : undefined}
          />
        </Tooltip>
      ))}
    </FieldOrEmpty>
  );
};
export default ItemParticipants;
