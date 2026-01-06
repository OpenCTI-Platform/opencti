import { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipStixCoreRelationshipsLines, { stixCoreRelationshipStixCoreRelationshipsLinesQuery } from './StixCoreRelationshipStixCoreRelationshipsLines';
import Card from '../../../../components/common/card/Card';

class StixCoreRelationshipStixCoreRelationships extends Component {
  render() {
    const { t, entityId, relationshipType } = this.props;
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
              <Card title={t('Linked entities')}>
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
  }
}

StixCoreRelationshipStixCoreRelationships.propTypes = {
  entityId: PropTypes.string,
  relationshipType: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
)(StixCoreRelationshipStixCoreRelationships);
