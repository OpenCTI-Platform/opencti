import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import { graphql, useFragment } from 'react-relay';
import StixCoreObjectLabels from '@components/common/stix_core_objects/StixCoreObjectLabels';
import { NarrativeLine_node$data, NarrativeLine_node$key } from '@components/techniques/narratives/__generated__/NarrativeLine_node.graphql';
import Tooltip from '@mui/material/Tooltip';
import Checkbox from '@mui/material/Checkbox';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilled } from '../../../../utils/String';

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
    color: theme.palette.text.primary,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
}));

const narrativeLineFragment = graphql`
  fragment NarrativeLine_node on Narrative {
    id
    name
    description
    created
    modified
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
  }
`;

interface NarrativeLineProps {
  node: NarrativeLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  selectedElements: Record<string, NarrativeLine_node$data>;
  deSelectedElements: Record<string, NarrativeLine_node$data>;
  onToggleEntity: (
    entity: NarrativeLine_node$data,
    event?: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onToggleShiftEntity: (
    index: number,
    entity: NarrativeLine_node$data,
    event?: React.SyntheticEvent
  ) => void;
  index: number;
  redirectionMode: string;
}
export const NarrativeLine: FunctionComponent<NarrativeLineProps> = ({
  dataColumns,
  node,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const { fd } = useFormatter();
  const data = useFragment(narrativeLineFragment, node);
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      component={Link}
      to={`/dashboard/techniques/narratives/${data.id}`}
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
          edge="start"
          checked={
            (selectAll && !(data.id in (deSelectedElements || {})))
            || data.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type="Narrative" />
      </ListItemIcon>
      <ListItemText
        primary={
          <>
            <Tooltip title={data.name}>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {data.name}
              </div>
            </Tooltip>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.description.width }}
            >
              {emptyFilled(data.description)}
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
              style={{ width: dataColumns.created.width }}
            >
              {fd(data.created)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.modified.width }}
            >
              {fd(data.modified)}
            </div>
          </>
            }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};

export const NarrativeLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();

  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
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
          <>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
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
              style={{ width: dataColumns.description.width }}
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
              style={{ width: dataColumns.objectLabel.width }}
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
              style={{ width: dataColumns.created.width }}
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
              style={{ width: dataColumns.modified.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
          </>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined color="disabled" />
      </ListItemIcon>
    </ListItem>
  );
};
