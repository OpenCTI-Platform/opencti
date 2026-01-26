import { FunctionComponent } from 'react';
import { stixDomainObjectMutation } from '@components/common/stix_domain_objects/StixDomainObjectHeader';
import Tooltip from '@mui/material/Tooltip';
import { truncate } from '../utils/String';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../utils/hooks/useGranted';
import FieldOrEmpty from './FieldOrEmpty';
import { commitMutation, defaultCommitMutation } from '../relay/environment';
import Tag from './common/tag/Tag';

type Node = {
  readonly entity_type: string;
  readonly id: string;
  readonly name: string;
};

type Props = {
  assignees: ReadonlyArray<Node>;
  stixDomainObjectId: string;
};

const ItemAssignees: FunctionComponent<Props> = ({ assignees, stixDomainObjectId }) => {
  const canUpdateKnowledge = useGranted([KNOWLEDGE_KNUPDATE]);
  const handleRemoveAssignee = (removedId: string) => {
    const values = assignees.filter((assignee) => assignee.id !== removedId);
    const valuesIds = values.map((value) => value.id);
    commitMutation({
      mutation: stixDomainObjectMutation,
      variables: {
        id: stixDomainObjectId,
        input: {
          key: 'objectAssignee',
          value: valuesIds,
        },
      },
      ...defaultCommitMutation,
    });
  };
  return (
    <FieldOrEmpty source={assignees}>
      {assignees.map((assignee) => (
        <Tooltip key={assignee.id} title={assignee.name}>
          <Tag
            key={assignee.id}
            label={truncate(assignee.name, 25)}
            onDelete={canUpdateKnowledge ? () => (handleRemoveAssignee(assignee.id)) : undefined}
          />
        </Tooltip>
      ))}
    </FieldOrEmpty>
  );
};

export default ItemAssignees;
