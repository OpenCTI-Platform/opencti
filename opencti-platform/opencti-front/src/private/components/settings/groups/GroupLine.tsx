import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircleOutlined, DoNotDisturbOnOutlined, KeyboardArrowRightOutlined, ReportGmailerrorred } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { Link } from 'react-router';
import { styled } from '@mui/material/styles';
import { GroupLine_node$data } from '@components/settings/groups/__generated__/GroupLine_node.graphql';
import Tooltip from '@mui/material/Tooltip';
import DangerZoneChip from '@components/common/danger_zone/DangerZoneChip';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface GroupLineProps {
  dataColumns: DataColumns;
  node: GroupLine_node$data;
}

const GroupLineComponent: React.FC<GroupLineProps> = (props) => {
  const { fd, t_i18n } = useFormatter();
  const { dataColumns, node } = props;
  const { isSensitive } = useSensitiveModifications('groups', node.standard_id);

  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      component={Link}
      to={`/dashboard/settings/accesses/groups/${node.id}`}
    >
      <ListItemText
        primary={(
          <>
            <BodyItem
              style={{ width: dataColumns.name.width, display: 'flex', alignItems: 'center', gap: '8px' }}
            >
              <span>{node.name}</span>
              {isSensitive && <DangerZoneChip />}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.default_assignation.width }}
            >
              {node.default_assignation ? (
                <CheckCircleOutlined fontSize="small" color="success" />
              ) : (
                <DoNotDisturbOnOutlined fontSize="small" color="primary" />
              )}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.auto_new_marking.width }}
            >
              {node.auto_new_marking ? (
                <CheckCircleOutlined fontSize="small" color="success" />
              ) : (
                <DoNotDisturbOnOutlined fontSize="small" color="primary" />
              )}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.no_creators.width }}
            >
              {node.no_creators ? (
                <CheckCircleOutlined fontSize="small" color="success" />
              ) : (
                <DoNotDisturbOnOutlined fontSize="small" color="primary" />
              )}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.group_confidence_level.width }}
            >
              {node.group_confidence_level?.max_confidence ?? (
                <Tooltip
                  title={t_i18n('This group does not have a Max Confidence Level, members might not be able to create data.')}
                >
                  <ReportGmailerrorred fontSize="small" color="error" />
                </Tooltip>
              )}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.created_at.width }}
            >
              {fd(node.created_at)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.updated_at.width }}
            >
              {fd(node.updated_at)}
            </BodyItem>
          </>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const GroupLine = createFragmentContainer(GroupLineComponent, {
  node: graphql`
    fragment GroupLine_node on Group {
      id
      name
      standard_id
      default_assignation
      no_creators
      auto_new_marking
      group_confidence_level {
        max_confidence
      }
      created_at
      updated_at
    }
  `,
});

export const GroupLineDummy: React.FC<Pick<GroupLineProps, 'dataColumns'>> = ({ dataColumns }) => {
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={<KeyboardArrowRightOutlined />}
    >
      <ListItemIcon sx={{ color: (theme) => theme.palette.grey?.[700] }}>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.default_assignation.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.auto_new_marking.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.group_confidence_level.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.created_at.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.updated_at.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
          </div>
        )}
      />
    </ListItem>
  );
};
