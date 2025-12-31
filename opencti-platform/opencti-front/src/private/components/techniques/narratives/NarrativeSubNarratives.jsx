import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import IconButton from '@common/button/IconButton';
import { SpeakerNotesOutlined, LinkOff } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import AddSubNarrative from './AddSubNarrative';
import { addSubNarrativesMutationRelationDelete } from './AddSubNarrativesLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

class NarrativeSubNarrativesComponent extends Component {
  removeSubNarrative(subNarrativeEdge) {
    commitMutation({
      mutation: addSubNarrativesMutationRelationDelete,
      variables: {
        fromId: subNarrativeEdge.node.id,
        toId: this.props.narrative.id,
        relationship_type: 'subnarrative-of',
      },
      updater: (store) => {
        const node = store.get(this.props.narrative.id);
        const subNarratives = node.getLinkedRecord('subNarratives');
        const edges = subNarratives.getLinkedRecords('edges');
        const newEdges = filter(
          (n) => n.getLinkedRecord('node').getValue('id')
            !== subNarrativeEdge.node.id,
          edges,
        );
        subNarratives.setLinkedRecords(newEdges, 'edges');
      },
    });
  }

  render() {
    const { t, narrative } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Subnarratives')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AddSubNarrative
            narrative={narrative}
            narrativeSubNarratives={narrative.subNarratives.edges}
          />
        </Security>
        <div className="clearfix" />
        <List style={{ marginTop: -10 }}>
          {narrative.subNarratives.edges.map((subNarrativeEdge) => {
            const subNarrative = subNarrativeEdge.node;
            return (
              <ListItem
                key={subNarrative.id}
                dense={true}
                divider={true}
                secondaryAction={(
                  <IconButton
                    aria-label="Remove"
                    onClick={this.removeSubNarrative.bind(
                      this,
                      subNarrativeEdge,
                    )}
                  >
                    <LinkOff />
                  </IconButton>
                )}
              >
                <ListItemButton
                  component={Link}
                  to={`/dashboard/techniques/narratives/${subNarrative.id}`}
                >
                  <ListItemIcon>
                    <SpeakerNotesOutlined color="primary" />
                  </ListItemIcon>
                  <ListItemText primary={subNarrative.name} />
                </ListItemButton>
              </ListItem>
            );
          })}
        </List>
      </div>
    );
  }
}

NarrativeSubNarrativesComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  narrative: PropTypes.object,
};

const NarrativeSubNarratives = createFragmentContainer(
  NarrativeSubNarrativesComponent,
  {
    narrative: graphql`
      fragment NarrativeSubNarratives_narrative on Narrative {
        id
        name
        parent_types
        entity_type
        subNarratives {
          edges {
            node {
              id
              parent_types
              name
              description
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n)(NarrativeSubNarratives);
