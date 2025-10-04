import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { LayersClearOutlined, MoreVert } from '@mui/icons-material';
import Slide, { SlideProps } from '@mui/material/Slide';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import { RetentionLinesPaginationQuery$variables } from '@private/components/settings/retention/__generated__/RetentionLinesPaginationQuery.graphql';
import { RetentionLine_node$key } from '@private/components/settings/retention/__generated__/RetentionLine_node.graphql';
import { InformationOutline } from 'mdi-material-ui';
import { useFormatter } from '../../../../components/i18n';
import RetentionPopover from './RetentionPopover';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { DataColumns } from '../../../../components/list_lines';
import { chipInListBasicStyle } from '../../../../utils/chipStyle';
import { Box, Chip, ListItem, ListItemIcon, ListItemText, Skeleton, Tooltip } from '@components';

const Transition = React.forwardRef((props: SlideProps, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

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
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  chipInList: {
    ...chipInListBasicStyle,
    width: 100,
    textTransform: 'uppercase',
  },
}));

const RetentionLineFragment = graphql`
    fragment RetentionLine_node on RetentionRule {
        id
        name
        max_retention
        retention_unit
        last_execution_date
        remaining_count
        filters
        scope
    }
`;

interface RetentionLineProps {
  dataColumns: DataColumns;
  node: RetentionLine_node$key;
  paginationOptions: RetentionLinesPaginationQuery$variables;
}

export const RetentionLine: FunctionComponent<RetentionLineProps> = ({ dataColumns, node, paginationOptions }) => {
  const classes = useStyles();
  const { nsdt, n, t_i18n } = useFormatter();
  const data = useFragment(RetentionLineFragment, node);
  const filters = deserializeFilterGroupForFrontend(data.filters);
  let scopeColor = 'warning';
  let appliedOnContent = t_i18n('Everything');
  if (data.scope === 'file') {
    scopeColor = 'secondary';
    appliedOnContent = t_i18n('Global files');
  } else if (data.scope === 'workbench') {
    scopeColor = 'primary';
    appliedOnContent = t_i18n('Global workbenches');
  }
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={
        <RetentionPopover
          retentionRuleId={data.id}
          paginationOptions={paginationOptions}
        />
      }
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <LayersClearOutlined/>
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div className={classes.bodyItem} style={{ width: dataColumns.name.width }}>
              {data.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.max_retention.width }}
            >
              {data.max_retention} {t_i18n(data.retention_unit)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.last_execution_date.width }}
            >
              {nsdt(data.last_execution_date)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.remaining_count.width }}
            >
              {n(data.remaining_count)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.scope.width }}
            >
              <Chip
                color={scopeColor as 'warning' | 'secondary' | 'primary'}
                classes={{ root: classes.chipInList }}
                label={t_i18n(data.scope.toUpperCase())}
                variant="outlined"
              />
            </div>
            {isFilterGroupNotEmpty(filters) ? (
              <FilterIconButton
                filters={filters}
                dataColumns={dataColumns}
                styleNumber={3}
                redirection
              />
            ) : (
              <div className={classes.bodyItem} style={{ width: dataColumns.filters.width }}>
                <span>{appliedOnContent}</span>
                {data.scope !== 'knowledge'
                  && <Tooltip
                    title={`${t_i18n('Files contained in')} ${t_i18n('Data')}/${t_i18n('Import')}`}
                     >
                    <InformationOutline
                      fontSize="small"
                      color="primary"
                      style={{ position: 'absolute', marginLeft: 10 }}
                    />
                  </Tooltip>
                }
              </div>
            )}
          </div>
          }
      />
    </ListItem>
  );
};

export const RetentionLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={
        <Box sx={{ root: classes.itemIconDisabled }}>
          <MoreVert/>
        </Box>
      }
    >
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
              style={{ width: dataColumns.max_retention.width }}
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
              style={{ width: dataColumns.last_execution_date.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="20%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.remaining_count.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="20%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.scope.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="70%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.filters.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="70%"
                height="100%"
              />
            </div>
          </div>
          }
      />
    </ListItem>
  );
};
