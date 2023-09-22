import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { hexToRGB, itemColor } from '../Colors';
import RelationShipFromAndTo from './RelationShipFromAndTo';
import ItemMarkings from '../../components/ItemMarkings';
import { useFormatter } from '../../components/i18n';
import type { SelectedEntity } from './EntitiesDetailsRightBar';

const useStyles = makeStyles({
  label: {
    marginTop: '20px',
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    width: 120,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
});
interface BasicRelationshipDetailsProps {
  relation: SelectedEntity,
}
const BasicRelationshipDetails: FunctionComponent<BasicRelationshipDetailsProps> = ({ relation }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  return (
    <div>
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
            {t('Relation type')}
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
            label={t(`relationship_${relation.relationship_type}`)}
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
            {t('Marking')}
        </Typography>
        {relation.markedBy
        && relation.markedBy.length > 0 ? (
            <ItemMarkings
                markingDefinitionsEdges={relation.markedBy.map((marking) => ({ node: marking }))}
                limit={2}
            />
          ) : (
            '-'
          )}
    </div>
  );
};

export default BasicRelationshipDetails;
