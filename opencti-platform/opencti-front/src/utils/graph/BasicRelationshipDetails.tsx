import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { hexToRGB } from '../Colors';
import RelationShipFromAndTo from './RelationShipFromAndTo';
import ItemMarkings from '../../components/ItemMarkings';
import { useFormatter } from '../../components/i18n';
import type { SelectedEntity } from './EntitiesDetailsRightBar';
import itemColor from '../../components/ItemColor';

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
  relation: SelectedEntity,
}
const BasicRelationshipDetails: FunctionComponent<BasicRelationshipDetailsProps> = ({ relation }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const relationshipType = relation.relationship_type ?? '';
  return (
    <div>
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Relation type')}
      </Typography>
      <Chip
        classes={{ root: classes.chipInList }}
        style={{
          backgroundColor: hexToRGB(
            itemColor(relationshipType),
            0.08,
          ),
          color: itemColor(relationshipType),
          border: `1px solid ${itemColor(
            relationshipType,
          )}`,
        }}
        label={t_i18n(`relationship_${relationshipType}`)}
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
