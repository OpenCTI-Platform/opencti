import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Avatar from '@mui/material/Avatar';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixSightingRelationshipExternalReferencesLines, { stixSightingRelationshipExternalReferencesLinesQuery } from './StixSightingRelationshipExternalReferencesLines';
import Card from '@common/card/Card';

class StixSightingRelationshipExternalReferences extends Component {
  render() {
    const { t, stixSightingRelationshipId } = this.props;
    return (
      <QueryRenderer
        query={stixSightingRelationshipExternalReferencesLinesQuery}
        variables={{ id: stixSightingRelationshipId, count: 200 }}
        render={({ props }) => {
          if (props) {
            return (
              <StixSightingRelationshipExternalReferencesLines
                stixSightingRelationshipId={stixSightingRelationshipId}
                data={props}
              />
            );
          }
          return (
            <div style={{ height: '100%' }}>
              <Card title={t('External references')}>
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}
                    >
                      <ListItemIcon>
                        <Avatar sx={{ width: 24, height: 24 }}>
                          {i}
                        </Avatar>
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

StixSightingRelationshipExternalReferences.propTypes = {
  stixSightingRelationshipId: PropTypes.string,
  limit: PropTypes.number,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default inject18n(StixSightingRelationshipExternalReferences);
