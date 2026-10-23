import React, { FunctionComponent } from 'react';
import { Link } from 'react-router';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { OrganizationLine_node$key } from '@components/entities/organizations/__generated__/OrganizationLine_node.graphql';
import { DraftChip } from '@components/common/draft/DraftChip';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface OrganizationLineProps {
  node: OrganizationLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
}

const organizationLineFragment = graphql`
    fragment OrganizationLine_node on Organization {
        id
        x_opencti_organization_type
        name
        created
        modified
        draftVersion {
            draft_id
            draft_operation
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
    }
`;
export const OrganizationLine: FunctionComponent<OrganizationLineProps> = ({
  dataColumns,
  node,
  onLabelClick,
}) => {
  const { fd } = useFormatter();
  const data = useFragment(organizationLineFragment, node);
  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      component={Link}
      to={`/dashboard/entities/organizations/${data.id}`}
    >
      <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
        <ItemIcon type="Organization" />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
              {data.draftVersion && (<DraftChip />)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.x_opencti_organization_type.width }}
            >
              <FieldOrEmpty source={data.x_opencti_organization_type}>{data.x_opencti_organization_type}</FieldOrEmpty>
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={data.objectLabel}
                onClick={onLabelClick.bind(this)}
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.created.width }}
            >
              {fd(data.created)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.modified.width }}
            >
              {fd(data.modified)}
            </BodyItem>
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const OrganizationLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  return (
    <ListItem sx={{ paddingLeft: '10px', height: 50 }} divider={true}>
      <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
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
              style={{ width: dataColumns.x_opencti_organization_type.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.objectLabel.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.created.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.modified.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </BodyItem>
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
