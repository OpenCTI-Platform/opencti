import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import { CancelOutlined, PersonOutline } from '@mui/icons-material';
import Chip from '@mui/material/Chip';
import { stixDomainObjectMutation } from '@components/common/stix_domain_objects/StixDomainObjectHeader';
import Tooltip from '@mui/material/Tooltip';
import FieldOrEmpty from './FieldOrEmpty';
import type { Theme } from './Theme';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../utils/hooks/useGranted';
import { truncate } from '../utils/String';
import { commitMutation, defaultCommitMutation } from '../relay/environment';

interface ItemParticipantsProps {
  participants: {
    readonly entity_type: string
    readonly id: string
    readonly name: string
  }[];
  stixDomainObjectId: string;
}

const ItemParticipants: FunctionComponent<ItemParticipantsProps> = ({ participants, stixDomainObjectId }) => {
  const theme = useTheme<Theme>();
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
          <Chip
            key={participant.id}
            variant="outlined"
            icon={<PersonOutline color={'primary'} />}
            label={truncate(participant.name, 25).toUpperCase()}
            style={{
              color: theme.palette.primary.main,
              borderColor: theme.palette.primary.main,
              margin: '0 7px 7px 0',
              borderRadius: theme.borderRadius,
            }}
            onDelete={canUpdateKnowledge ? () => (handleRemoveParticipant(participant.id)) : undefined}
            deleteIcon={
              <CancelOutlined
                style={{ color: theme.palette.primary.main }}
              />
            }
          />
        </Tooltip>
      ))}
    </FieldOrEmpty>
  );
};
export default ItemParticipants;
