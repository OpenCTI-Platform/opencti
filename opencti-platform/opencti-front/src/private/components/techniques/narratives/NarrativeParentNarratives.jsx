import React from 'react';
import * as PropTypes from 'prop-types';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import { SpeakerNotesOutlined } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import { ListItemButton } from '@mui/material';
import { truncate } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import Label from '../../../../components/common/label/Label';

const NarrativeParentNarrativesComponent = (props) => {
  const { t_i18n } = useFormatter();
  const { narrative } = props;
  return (
    <div style={{ height: '100%' }}>
      <Label>
        {t_i18n('Parent narratives')}
      </Label>
      <List sx={{ py: 0 }}>
        {narrative.parentNarratives.edges.map((parentNarrativeEdge) => {
          const parentNarrative = parentNarrativeEdge.node;
          return (
            <ListItemButton
              key={parentNarrative.id}
              dense={true}
              divider={true}
              component={Link}
              to={`/dashboard/techniques/narratives/${parentNarrative.id}`}
            >
              <ListItemIcon>
                <SpeakerNotesOutlined color="primary" />
              </ListItemIcon>
              <ListItemText
                primary={parentNarrative.name}
                secondary={truncate(parentNarrative.description, 50)}
              />
            </ListItemButton>
          );
        })}
      </List>
    </div>
  );
};

NarrativeParentNarrativesComponent.propTypes = {
  classes: PropTypes.object,
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

export default NarrativeParentNarratives;
