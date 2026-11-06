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
import StixCoreRelationshipExternalReferencesLines, { stixCoreRelationshipExternalReferencesLinesQuery } from './StixCoreRelationshipExternalReferencesLines';
import Card from '../../../../components/common/card/Card';

class StixCoreRelationshipExternalReferences extends Component {
  render() {
    const { t, stixCoreRelationshipId } = this.props;
    return (
      <QueryRenderer
        query={stixCoreRelationshipExternalReferencesLinesQuery}
        variables={{ id: stixCoreRelationshipId, count: 200 }}
        render={({ props }) => {
          if (props) {
            return (
              <StixCoreRelationshipExternalReferencesLines
                stixCoreRelationshipId={stixCoreRelationshipId}
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

StixCoreRelationshipExternalReferences.propTypes = {
  stixCoreRelationshipId: PropTypes.string,
  limit: PropTypes.number,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default inject18n(StixCoreRelationshipExternalReferences);
