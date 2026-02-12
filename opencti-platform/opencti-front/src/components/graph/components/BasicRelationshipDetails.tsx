import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import RelationShipFromAndTo from './RelationShipFromAndTo';
import ItemMarkings from '../../ItemMarkings';
import { useFormatter } from '../../i18n';
import { GraphLink } from '../graph.types';
import Label from '@common/label/Label';
import Tag from '@common/tag/Tag';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  label: {
    marginTop: 20,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    width: 120,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
});
interface BasicRelationshipDetailsProps {
  relation: GraphLink;
}
const BasicRelationshipDetails: FunctionComponent<BasicRelationshipDetailsProps> = ({ relation }) => {
  const classes = useStyles();
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
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
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
