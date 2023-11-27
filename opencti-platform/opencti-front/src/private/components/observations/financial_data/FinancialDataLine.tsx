import React, { FunctionComponent } from 'react';
import StixCoreObjectLabels from '@components/common/stix_core_objects/StixCoreObjectLabels';
import { KeyboardArrowRight } from '@mui/icons-material';
import { Checkbox, Chip, Skeleton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { makeStyles } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import ItemIcon from 'src/components/ItemIcon';
import ItemMarkings from 'src/components/ItemMarkings';
import { Theme } from 'src/components/Theme';
import { useFormatter } from 'src/components/i18n';
import { DataColumns } from 'src/components/list_lines';
import { hexToRGB, itemColor } from 'src/utils/Colors';
import { FinancialDataLine_node$data, FinancialDataLine_node$key } from './__generated__/FinancialDataLine_node.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 150,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
}));

const financialDataLineFragment = graphql`
  fragment FinancialDataLine_node on StixCyberObservable {
    id
    entity_type
    parent_types
    observable_value
    created_at
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    creators {
      id
      name
    }
  }
`;

interface FinancialDataLineComponentProps {
  node: FinancialDataLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: (
    key: string,
    id: string,
    value: string,
    event: React.SyntheticEvent
  ) => void;
  selectedElements: Record<string, FinancialDataLine_node$data>;
  deSelectedElements: Record<string, FinancialDataLine_node$data>;
  onToggleEntity: (
    entity: FinancialDataLine_node$data,
    event?: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onToggleShiftEntity: (
    index: number,
    entity: FinancialDataLine_node$data,
    event?: React.SyntheticEvent
  ) => void;
  index: number;
}

export const FinancialDataLine: FunctionComponent<FinancialDataLineComponentProps> = ({
  node,
  dataColumns,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const { t_i18n, nsdt } = useFormatter();
  const data = useFragment(financialDataLineFragment, node);
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      component={Link}
      to={`/dashboard/observations/financial-data/${data.id}`}
    >
      <ListItemIcon
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, data, event)
          : onToggleEntity(data, event))
        }
      >
        <Checkbox
          edge='start'
          checked={
            (selectAll && !(data.id in (deSelectedElements || {})))
            || data.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type={data.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              <Chip
                classes={{ root: classes.chipInList }}
                style={{
                  backgroundColor: hexToRGB(itemColor(data.entity_type), 0.08),
                  color: itemColor(data.entity_type),
                  border: `1px solid ${itemColor(data.entity_type)}`,
                }}
                label={t_i18n(`entity_${data.entity_type}`)}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.observable_value.width }}
            >
              {data.observable_value}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.createdBy.width }}
            >
              {data.createdBy?.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.creator.width }}
            >
              {(data.creators ?? []).map((c) => c?.name).join(', ')}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={data.objectLabel}
                onClick={onLabelClick}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created_at.width }}
            >
              {nsdt(data.created_at)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectMarking.width }}
            >
              <ItemMarkings
                variant="inList"
                markingDefinitions={data.objectMarking}
                limit={1}
              />
            </div>
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItem>
  );
};

export const FinancialDataLineDummy: FunctionComponent = () => {
  const classes = useStyles();

  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon
        classes={{ root: classes.itemIconDisabled }}
        style={{ minWidth: 40 }}
      >
        <Checkbox edge="start" disabled={true} disableRipple={true} />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
          </div>
        }
      />
    </ListItem>
  );
};
