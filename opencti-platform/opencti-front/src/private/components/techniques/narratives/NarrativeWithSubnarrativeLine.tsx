import React, {FunctionComponent} from 'react';
import {Link} from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import {KeyboardArrowRightOutlined} from '@mui/icons-material';
import List from '@mui/material/List';
import Skeleton from '@mui/material/Skeleton';
import {useFormatter} from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import makeStyles from "@mui/styles/makeStyles";
import {Theme} from "@mui/material/styles/createTheme";
import {graphql, useFragment} from "react-relay";
import {
    NarrativeWithSubnarrativeLine_node$data,
    NarrativeWithSubnarrativeLine_node$key
} from "@components/techniques/narratives/__generated__/NarrativeWithSubnarrativeLine_node.graphql";

const useStyles = makeStyles<Theme>((theme) => ({
  item: {},
  itemNested: {
    paddingLeft: theme.spacing(4),
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  name: {
    width: '20%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  description: {
    width: '70%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    color: '#a5a5a5',
    fontSize: 12,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
}));

const narrativeWithSubnarrativeLineFragment = graphql`
    fragment NarrativeWithSubnarrativeLine_node on Narrative {
        id
        name
        description
        objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
        }
        subNarratives {
            edges {
                node {
                    id
                    name
                    description
                    objectMarking {
                        id
                        definition_type
                        definition
                        x_opencti_order
                        x_opencti_color
                    }
                }
            }
        }
    }`

interface NarrativeWithSubnarrativeLineProps {
  node: NarrativeWithSubnarrativeLine_node$key;
    subNarratives: Array<NarrativeWithSubnarrativeLine_node$key>,
    isSubNarrative: boolean,
  onToggleEntity: (
      entity: NarrativeWithSubnarrativeLine_node$data,
      event?: React.SyntheticEvent
  ) => void;
  onToggleShiftEntity: (
      index: number,
      entity: NarrativeWithSubnarrativeLine_node$data,
      event?: React.SyntheticEvent
  ) => void;
  index: number;
  redirectionMode: string;
}

export const NarrativeWithSubnarrativeLine: FunctionComponent<NarrativeWithSubnarrativeLineProps> = ({
     node,
     subNarratives,
   }) => {
     const classes = useStyles();
     const { t_i18n } = useFormatter();
     const narrativeData = useFragment(narrativeWithSubnarrativeLineFragment, node);
     const subNarrativeData = subNarratives.map((subNarrative) => {
        const subNarrativeFragment = useFragment(
            narrativeWithSubnarrativeLineFragment,
            subNarrative
        );
        return {
            ...subNarrativeFragment,
            "$fragmentSpreads": narrativeWithSubnarrativeLineFragment,
        };
    });
    return (
      <div>
          <ListItem
              classes={{ root: subNarratives.length > 0 ? classes.itemNested : classes.item }}
              divider={true}
              button={true}
              component={Link}
              to={`/dashboard/techniques/narratives/${narrativeData.id}`}
          >
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ItemIcon
                      type="Narrative"
                      size={subNarratives.length > 0 ? 'small' : 'medium'}
                  />
              </ListItemIcon>
          <ListItemText
            primary={
              <>
                <div className={classes.name}>{narrativeData.name}</div>
                <div className={classes.description}>
                    {narrativeData.description && narrativeData.description.length > 0
                    ? narrativeData.description
                    : t_i18n('This narrative does not have any description.')}
                </div>
              </>
                        }
          />
          <ListItemIcon classes={{ root: classes.goIcon }}>
            <KeyboardArrowRightOutlined />
          </ListItemIcon>
        </ListItem>
        {subNarratives && subNarratives.length > 0 && (
            <List style={{ margin: 0, padding: 0 }}>
                {subNarrativeData.map((subNarrativeData) => (
                    <NarrativeWithSubnarrativeLine
                        key={subNarrativeData.id}
                        node={subNarrativeData}
                        isSubNarrative={true}
                    />
                ))}
            </List>
        )}
      </div>
    );
  };


export const NarrativeLineDummy = ({}: {
}) => {
    const classes = useStyles();
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              height={20}
            />
                    }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined color="disabled" />
        </ListItemIcon>
      </ListItem>
    );
  }
}

