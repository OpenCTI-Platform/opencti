import React from 'react';
import { Link } from 'react-router';
import { Checkbox } from '@filigran/design-system';
import { KeyboardArrowRight } from '@mui/icons-material';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import ItemEntityType from '../../../../components/ItemEntityType';
import ItemIcon from '../../../../components/ItemIcon';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { EMPTY_VALUE } from '../../../../utils/String';
import { resolveLink } from '../../../../utils/Entity';
import type { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import { useFragment } from 'react-relay';
import { stixCoreRelationshipsFragment } from '@components/common/stix_core_relationships/StixCoreRelationships';

export type ReportRelationshipNode = {
  id: string;
  entity_type: string;
  relationship_type: string;
  created_at: string;
  createdBy?: { name: string } | null;
  objectMarking?: ReadonlyArray<{ definition?: string | null }> | null;
  from?: { id: string; entity_type?: string; representative?: { main?: string | null } } | null;
  to?: { id: string; entity_type?: string; representative?: { main?: string | null } } | null;
};

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: bodyItemStyle,
  goIcon: {
    position: 'absolute',
    right: -10,
  },
}));

interface ReportStixCoreRelationshipsLineProps {
  dataColumns: DataColumns;
  node: ReportRelationshipNode;
  onToggleEntity: (node: ReportRelationshipNode, event: React.SyntheticEvent) => void;
  selectedElements: Record<string, ReportRelationshipNode>;
  deSelectedElements: Record<string, ReportRelationshipNode>;
  selectAll: boolean;
}

const ReportStixCoreRelationshipsLine = ({
  dataColumns,
  node,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
}: ReportStixCoreRelationshipsLineProps) => {
  const classes = useStyles();
  const relationship = useFragment(stixCoreRelationshipsFragment, node as never) as ReportRelationshipNode;
  const from = relationship.from;
  const to = relationship.to;
  const isRestricted = !from || !to;
  const relationshipLink = from
    ? `${resolveLink(from.entity_type)}/${from.id}/knowledge/relations/${relationship.id}`
    : to
      ? `${resolveLink(to.entity_type)}/${to.id}/knowledge/relations/${relationship.id}`
      : undefined;

  return (
    <ListItemButton
      classes={{ root: classes.item }}
      divider={true}
      component={Link}
      to={relationshipLink ?? '#'}
    >
      <ListItemIcon
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
        onClick={(event) => onToggleEntity(relationship, event)}
      >
        <Checkbox
          aria-label="Select line"
          checked={
            (selectAll && !(relationship.id in (deSelectedElements || {})))
            || relationship.id in (selectedElements || {})
          }
        />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type={relationship.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <div className={classes.bodyItem} style={{ width: dataColumns.fromType.width }}>
              <ItemEntityType entityType={from?.entity_type ?? ''} isRestricted={!from} />
            </div>
            <div className={classes.bodyItem} style={{ width: dataColumns.fromName.width }}>
              {from ? getMainRepresentative(from) : EMPTY_VALUE}
            </div>
            <div className={classes.bodyItem} style={{ width: dataColumns.relationship_type.width }}>
              <ItemEntityType entityType={relationship.relationship_type} />
            </div>
            <div className={classes.bodyItem} style={{ width: dataColumns.toType.width }}>
              <ItemEntityType entityType={to?.entity_type ?? ''} isRestricted={!to} />
            </div>
            <div className={classes.bodyItem} style={{ width: dataColumns.toName.width }}>
              {to ? getMainRepresentative(to) : EMPTY_VALUE}
            </div>
            <div className={classes.bodyItem} style={{ width: dataColumns.createdBy.width }}>
              {relationship.createdBy?.name ?? EMPTY_VALUE}
            </div>
            <div className={classes.bodyItem} style={{ width: dataColumns.created_at.width }}>
              {relationship.created_at ?? EMPTY_VALUE}
            </div>
            <div className={classes.bodyItem} style={{ width: dataColumns.objectMarking.width }}>
              {isRestricted ? EMPTY_VALUE : relationship.objectMarking?.[0]?.definition ?? EMPTY_VALUE}
            </div>
          </div>
        )}
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const ReportStixCoreRelationshipsLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => (
  <ListItemButton divider={true} disabled>
    <ListItemText
      primary={Object.keys(dataColumns).map((key) => (
        <span key={key} style={{ display: 'inline-block', width: dataColumns[key].width }} />
      ))}
    />
  </ListItemButton>
);

export default ReportStixCoreRelationshipsLine;
