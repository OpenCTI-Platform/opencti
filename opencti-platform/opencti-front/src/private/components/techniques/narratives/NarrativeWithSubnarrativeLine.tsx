import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import List from '@mui/material/List';
import { useTheme } from '@mui/material/styles';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import { SubNarrativeNode } from '@components/techniques/narratives/NarrativesWithSubnarrativesLines';
import { useFragment } from 'react-relay';
import { NarrativeLine_node$data, NarrativeLine_node$key } from '@components/techniques/narratives/__generated__/NarrativeLine_node.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import { emptyFilled } from '../../../../utils/String';
import { narrativeLineFragment } from './NarrativeLine';

interface NarrativeWithSubnarrativeLineProps {
  isSubNarrative?: boolean;
  subNarratives?: SubNarrativeNode[];
  node: SubNarrativeNode | NarrativeLine_node$key;
}

const NarrativeWithSubnarrativeLine: FunctionComponent<NarrativeWithSubnarrativeLineProps> = ({ node, isSubNarrative }) => {
  const theme = useTheme();

  let data: SubNarrativeNode | NarrativeLine_node$data = node as SubNarrativeNode;
  if (!isSubNarrative) {
    data = useFragment(narrativeLineFragment, node as NarrativeLine_node$key);
  }

  const subNarratives: NarrativeWithSubnarrativeLineProps['subNarratives'] = ((data as NarrativeLine_node$data).subNarratives?.edges ?? []).map(({ node: subNode }) => subNode);

  return (
    <div>
      <ListItemButton
        style={{
          paddingLeft: isSubNarrative ? theme.spacing(4) : undefined,
        }}
        divider
        component={Link}
        to={`/dashboard/techniques/narratives/${data.id}`}
      >
        <ListItemIcon style={{ color: theme.palette.primary.main }}>
          <ItemIcon
            type="Narrative"
            size={isSubNarrative ? 'small' : 'medium'}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <>
              <div
                style={{
                  width: '30%',
                  height: 20,
                  lineHeight: '20px',
                  float: 'left',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {data.name}
              </div>
              <div
                style={{
                  height: 20,
                  fontSize: 13,
                  float: 'left',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  paddingRight: 10,
                  color: theme.palette.text.primary,
                }}
              >
                {emptyFilled(data.description)}
              </div>
            </>
              }
        />
        <ListItemIcon style={{ position: 'absolute', right: -10 }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItemButton>
      {subNarratives && subNarratives.length > 0 && (
        <List style={{ marginTop: 0, padding: 0 }}>
          {subNarratives.map((subNarrative) => (
            <NarrativeWithSubnarrativeLine key={subNarrative.id} node={subNarrative} isSubNarrative={true} />
          ))}
        </List>
      )}
    </div>
  );
};

export const NarrativeWithSubnarrativeLineDummy: FunctionComponent = () => {
  const theme = useTheme();

  return (
    <ListItem divider>
      <ListItemIcon style={{ color: theme.palette.primary.main }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <Skeleton animation="wave" variant="rectangular" width="90%" height={20} />
        }
      />
      <ListItemIcon style={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined color="disabled" />
      </ListItemIcon>
    </ListItem>
  );
};

export default NarrativeWithSubnarrativeLine;
