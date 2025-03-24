import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { hexToRGB, itemColor } from '../../../utils/Colors';
import RelationShipFromAndTo from './RelationShipFromAndTo';
import ItemMarkings from '../../ItemMarkings';
import { useFormatter } from '../../i18n';
import { GraphLink } from '../graph.types';

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
  relation: GraphLink,
}
const BasicRelationshipDetails: FunctionComponent<BasicRelationshipDetailsProps> = ({ relation }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  return (
    <div>
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Relation type')}
      </Typography>
      <Chip
        classes={{ root: classes.chipInList }}
        style={{
          backgroundColor: hexToRGB(
            itemColor(relation.relationship_type),
            0.08,
          ),
          color: itemColor(relation.relationship_type),
          border: `1px solid ${itemColor(
            relation.relationship_type,
          )}`,
        }}
        label={t_i18n(`relationship_${relation.relationship_type}`)}
      />
      {relation.source_id && (
        <RelationShipFromAndTo
          id={relation.source_id}
          direction={'From'}
        />
      )}
      {relation.target_id && (
        <RelationShipFromAndTo
          id={relation.target_id}
          direction={'To'}
        />
      )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Marking')}
      </Typography>
      {relation.markedBy && relation.markedBy.length > 0 ? (
        <ItemMarkings markingDefinitions={relation.markedBy} limit={2}/>
      ) : ('-')}
    </div>
  );
};

export default BasicRelationshipDetails;
