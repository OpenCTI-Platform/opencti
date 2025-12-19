import React from 'react';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import { AutoFix } from 'mdi-material-ui';
import Checkbox from '@mui/material/Checkbox';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import Chip from '@mui/material/Chip';
import IconButton from '@common/button/IconButton';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import ContainerStixCoreObjectPopover from './ContainerStixCoreObjectPopover';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import { renderObservableValue } from '../../../../utils/String';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemIcon from '../../../../components/ItemIcon';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import ItemEntityType from '../../../../components/ItemEntityType';
import { DraftChip } from '../draft/DraftChip';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
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
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  chip: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: 4,
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
    },
  },
  chipNoLink: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
}));

const ContainerStixCyberObservableLineComponent = (props) => {
  const {
    node,
    types,
    dataColumns,
    containerId,
    paginationOptions,
    onToggleShiftEntity,
    index,
    onToggleEntity,
    selectedElements,
    deSelectedElements,
    selectAll,
    setSelectedElements,
    enableReferences,
  } = props;
  const classes = useStyles();
  const { t_i18n, fd, n } = useFormatter();
  const refTypes = types ?? ['manual'];
  const isThroughInference = refTypes.includes('inferred');
  const isOnlyThroughInference = isThroughInference && !refTypes.includes('manual');
  const link = `/dashboard/observations/${
    node.entity_type === 'Artifact' ? 'artifacts' : 'observables'
  }/${node.id}`;
  const linkAnalyses = `${link}/analyses`;
  return (
    <ListItem
      divider={true}
      disablePadding
      secondaryAction={isOnlyThroughInference ? (
        <Tooltip title={t_i18n('Inferred knowledge')}>
          <AutoFix fontSize="small" style={{ marginLeft: -30 }} />
        </Tooltip>
      ) : (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ContainerStixCoreObjectPopover
            containerId={containerId}
            toId={node.id}
            toStandardId={node.standard_id}
            menuDisable={isOnlyThroughInference}
            relationshipType="object"
            paginationKey="Pagination_objects"
            paginationOptions={paginationOptions}
            selectedElements={selectedElements}
            setSelectedElements={setSelectedElements}
            enableReferences={enableReferences}
          />
        </Security>
      )}
    >
      <ListItemButton
        classes={{ root: classes.item }}
        component={Link}
        to={link}
      >
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 40 }}
          onClick={(event) => !isOnlyThroughInference
            && (event.shiftKey
              ? onToggleShiftEntity(index, node, event)
              : onToggleEntity(node, event))
          }
        >
          <Checkbox
            edge="start"
            disabled={isOnlyThroughInference}
            checked={
              (selectAll
                && !isOnlyThroughInference
                && !(node.id in deSelectedElements))
              || node.id in selectedElements
            }
            disableRipple={true}
          />
        </ListItemIcon>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={node.entity_type} />
        </ListItemIcon>
        <ListItemText
          primary={(
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <ItemEntityType entityType={node.entity_type} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.observable_value.width }}
              >
                {renderObservableValue(node)}
                {node.draftVersion && (<DraftChip />)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={node.objectLabel}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                {node.createdBy?.name ?? '-'}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                {fd(node.created_at)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.analyses.width }}
              >
                {[
                  'Note',
                  'Opinion',
                  'Course-Of-Action',
                  'Data-Component',
                  'Data-Source',
                ].includes(node.entity_type) ? (
                      <Chip
                        classes={{ root: classes.chipNoLink }}
                        label={n(node.containersNumber.total)}
                      />
                    ) : (
                      <Chip
                        classes={{ root: classes.chip }}
                        label={n(node.containersNumber.total)}
                        component={Link}
                        to={linkAnalyses}
                      />
                    )}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <ItemMarkings
                  variant="inList"
                  markingDefinitions={node.objectMarking ?? []}
                  limit={1}
                />
              </div>
            </div>
          )}
        />
      </ListItemButton>
    </ListItem>
  );
};

export const ContainerStixCyberObservableLine = createFragmentContainer(
  ContainerStixCyberObservableLineComponent,
  {
    node: graphql`
      fragment ContainerStixCyberObservableLine_node on StixCyberObservable {
        id
        draftVersion {
          draft_id
          draft_operation
        }
        standard_id
        observable_value
        entity_type
        parent_types
        created_at
        ... on IPv4Addr {
          countries {
            edges {
              node {
                name
                x_opencti_aliases
              }
            }
          }
        }
        ... on IPv6Addr {
          countries {
            edges {
              node {
                name
                x_opencti_aliases
              }
            }
          }
        }
        objectLabel {
          id
          value
          color
        }
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
        containersNumber {
          total
        }
      }
    `,
  },
);

export const ContainerStixCyberObservableLineDummy = (props) => {
  const { dataColumns } = props;
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={(
        <IconButton classes={classes.itemIconDisabled} disabled={true} aria-haspopup="true">
          <MoreVert />
        </IconButton>
      )}
    >
      <ListItemIcon
        classes={{ root: classes.itemIconDisabled }}
        style={{ minWidth: 40 }}
      >
        <Checkbox edge="start" disabled={true} disableRipple={true} />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
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
              style={{ width: dataColumns.observable_value.width }}
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
              style={{ width: dataColumns.createdBy.width }}
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
              style={{ width: dataColumns.created_at.width }}
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
              style={{ width: dataColumns.analyses.width }}
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
              style={{ width: dataColumns.objectMarking.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={100}
                height="100%"
              />
            </div>
          </div>
        )}
      />
    </ListItem>
  );
};
