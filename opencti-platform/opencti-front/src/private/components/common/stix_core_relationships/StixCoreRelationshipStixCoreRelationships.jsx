import * as PropTypes from 'prop-types';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipStixCoreRelationshipsLines, { stixCoreRelationshipStixCoreRelationshipsLinesQuery } from './StixCoreRelationshipStixCoreRelationshipsLines';
import Card from '../../../../components/common/card/Card';

const StixCoreRelationshipStixCoreRelationships = (props) => {
  const { t_i18n } = useFormatter();
  const { entityId, relationshipType } = props;
  const paginationOptions = {
    fromOrToId: entityId,
    relationship_type: relationshipType,
    orderBy: 'created_at',
    orderMode: 'desc',
  };
  return (
    <QueryRenderer
      query={stixCoreRelationshipStixCoreRelationshipsLinesQuery}
      variables={{ count: 25, ...paginationOptions }}
      render={({ props }) => {
        if (props) {
          return (
            <StixCoreRelationshipStixCoreRelationshipsLines
              entityId={entityId}
              data={props}
              paginationOptions={paginationOptions}
            />
          );
        }
        return (
          <div style={{ height: '100%' }}>
            <Card title={t_i18n('Linked entities')}>
              <List>
                {Array.from(Array(5), (e, i) => (
                  <ListItem key={i} divider={true}>
                    <ListItemIcon>
                      <Skeleton
                        animation="wave"
                        variant="circular"
                        width={30}
                        height={30}
                      />
                    </ListItemIcon>
                    <ListItemText
                      primary={(
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                          style={{ marginBottom: 10 }}
                        />
                      )}
                      secondary={(
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                        />
                      )}
                    />
                  </ListItem>
                ))}
              </List>
            </Card>
          </div>
        );
      }}
    />
  );
};

StixCoreRelationshipStixCoreRelationships.propTypes = {
  entityId: PropTypes.string,
  relationshipType: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
};

export default StixCoreRelationshipStixCoreRelationships;
