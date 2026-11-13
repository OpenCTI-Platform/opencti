import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import RelationShipFromAndTo from './RelationShipFromAndTo';
import ItemMarkings from '../../ItemMarkings';
import { useFormatter } from '../../i18n';
import { GraphLink } from '../graph.types';
import Label from '@common/label/Label';
import Tag from '@common/tag/Tag';

interface BasicRelationshipDetailsProps {
  relation: GraphLink;
}
const BasicRelationshipDetails: FunctionComponent<BasicRelationshipDetailsProps> = ({ relation }) => {
  const { t_i18n } = useFormatter();
  return (
    <div>
      <Label>
        {t_i18n('Relation type')}
      </Label>
      <Tag
        label={t_i18n(`relationship_${relation.relationship_type}`)}
      />
      {relation.source_id && (
        <RelationShipFromAndTo
          id={relation.source_id}
          direction="From"
        />
      )}
      {relation.target_id && (
        <RelationShipFromAndTo
          id={relation.target_id}
          direction="To"
        />
      )}
      <Typography variant="h3" gutterBottom={true} sx={{ marginTop: '20px' }}>
        {t_i18n('Marking')}
      </Typography>
      <ItemMarkings
        markingDefinitions={relation.markedBy}
        limit={2}
      />
    </div>
  );
};

export default BasicRelationshipDetails;
