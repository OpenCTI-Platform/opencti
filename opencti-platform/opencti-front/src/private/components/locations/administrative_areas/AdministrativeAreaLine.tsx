import React, { FunctionComponent } from 'react';
import { Link } from 'react-router';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { DraftChip } from '@components/common/draft/DraftChip';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import { AdministrativeAreaLine_node$key } from './__generated__/AdministrativeAreaLine_node.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface AdministrativeAreaLineComponentProps {
  dataColumns: DataColumns;
  node: AdministrativeAreaLine_node$key;
}

const AdministrativeAreaFragment = graphql`
  fragment AdministrativeAreaLine_node on AdministrativeArea {
    id
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

export const AdministrativeAreaLine: FunctionComponent<
  AdministrativeAreaLineComponentProps
> = ({ dataColumns, node }) => {
  const { fd } = useFormatter();
  const data = useFragment(AdministrativeAreaFragment, node);
  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      component={Link}
      to={`/dashboard/locations/administrative_areas/${data.id}`}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <ItemIcon type="Administrative-Area" />
      </ListItemIcon>
      <ListItemText
        primary={(
          <>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
              {data.draftVersion && (<DraftChip />)}
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
          </>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const AdministrativeAreaLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  return (
    <ListItem sx={{ paddingLeft: '10px', height: 50 }} divider={true}>
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <>
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
              style={{ width: dataColumns.created.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.modified.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
          </>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined color="disabled" />
      </ListItemIcon>
    </ListItem>
  );
};
