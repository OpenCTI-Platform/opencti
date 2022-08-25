import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import { SpeakerNotesOutlined } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';

class NarrativeParentNarrativesComponent extends Component {
  render() {
    const { t, narrative } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Parent narratives')}
        </Typography>
        <List>
          {narrative.parentNarratives.edges.map((parentNarrativeEdge) => {
            const parentNarrative = parentNarrativeEdge.node;
            return (
              <ListItem
                key={parentNarrative.id}
                dense={true}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/arsenal/narratives/${parentNarrative.id}`}
              >
                <ListItemIcon>
                  <SpeakerNotesOutlined color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary={parentNarrative.name}
                  secondary={truncate(parentNarrative.description, 50)}
                />
              </ListItem>
            );
          })}
        </List>
      </div>
    );
  }
}

NarrativeParentNarrativesComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  attackPattern: PropTypes.object,
};

const NarrativeParentNarratives = createFragmentContainer(
  NarrativeParentNarrativesComponent,
  {
    narrative: graphql`
      fragment NarrativeParentNarratives_narrative on Narrative {
        id
        parentNarratives {
          edges {
            node {
              id
              name
              description
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n)(NarrativeParentNarratives);
