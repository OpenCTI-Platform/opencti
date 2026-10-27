import Tag from '@common/tag/Tag';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import { NotifierLine_node$data, NotifierLine_node$key } from './__generated__/NotifierLine_node.graphql';
import { NotifiersLinesPaginationQuery$variables } from './__generated__/NotifiersLinesPaginationQuery.graphql';
import NotifierPopover from './NotifierPopover';

const BodyItem = styled('div')({
  height: 25,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 5,

  display: 'flex',
  alignItems: 'center',
  minWidth: 0,
  width: '100%',
});

const BodyItemText = styled('span')({
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  minWidth: 0,
});

interface NotifierLineProps {
  node: NotifierLine_node$key | NotifierLine_node$data;
  dataColumns: DataColumns;
  paginationOptions: NotifiersLinesPaginationQuery$variables;
}

const NotifierLineFragment = graphql`
  fragment NotifierLine_node on Notifier {
    id
    entity_type
    name
    description
    notifier_connector {
      name
    }
  }
`;

const isNotifierData = (node: NotifierLine_node$key | NotifierLine_node$data): node is NotifierLine_node$data => !!(node as NotifierLine_node$data).id;

export const NotifierLine: FunctionComponent<NotifierLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const data = useFragment(NotifierLineFragment, !isNotifierData(node) ? node : null) ?? node as NotifierLine_node$data;

  return (
    <>
      <ListItem sx={{ paddingLeft: '10px', height: '50px' }} divider>
        <ListItemIcon sx={{ color: 'primary.main' }}>
          <ItemIcon type="Notifier" />
        </ListItemIcon>
        <ListItemText
          primary={(
            <div>
              <BodyItem style={{ width: dataColumns.connector.width }}>
                <Tag label={data.notifier_connector.name} />
              </BodyItem>
              <BodyItem style={{ width: dataColumns.name.width }}>
                <BodyItemText>
                  {data.name}
                </BodyItemText>
              </BodyItem>
              <BodyItem style={{ width: dataColumns.description.width, paddingRight: 40 }}>
                <BodyItemText>
                  {data.description}
                </BodyItemText>
              </BodyItem>
            </div>
          )}
        />
        <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
          <NotifierPopover data={data} paginationOptions={paginationOptions} />
        </ListItemIcon>
      </ListItem>
    </>
  );
};

export const NotifierLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  return (
    <ListItem sx={{ paddingLeft: '10px', height: '50px' }} divider={true}>
      <ListItemIcon sx={{ color: (theme) => theme.palette.grey?.[700] }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem style={{ width: dataColumns.connector.width }}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem style={{ width: dataColumns.name.width }}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem style={{ width: dataColumns.description.width }}>
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
