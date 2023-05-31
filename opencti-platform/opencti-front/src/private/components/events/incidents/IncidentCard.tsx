import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import Markdown from 'react-markdown';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import Avatar from '@mui/material/Avatar';
import { Fire } from 'mdi-material-ui';
import Skeleton from '@mui/material/Skeleton';

import makeStyles from '@mui/styles/makeStyles';
import remarkParse from 'remark-parse';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import { itemColor } from '../../../../utils/Colors';
import { Theme } from '../../../../components/Theme';
import { IncidentCard_node$key } from './__generated__/IncidentCard_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import { remarkGfm } from '../../../../components/ExpandableMarkdown';

const useStyles = makeStyles<Theme>((theme) => ({
  card: {
    width: '100%',
    height: 170,
    borderRadius: 6,
  },
  cardDummy: {
    width: '100%',
    height: 170,
    color: theme.palette.grey?.[700],
    borderRadius: 6,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    backgroundColor: theme.palette.grey?.[600],
  },
  icon: {
    margin: '10px 20px 0 0',
    fontSize: 40,
  },
  area: {
    width: '100%',
    height: '100%',
  },
  header: {
    height: 55,
    paddingBottom: 0,
    marginBottom: 0,
  },
  content: {
    width: '100%',
    paddingTop: 0,
  },
  description: {
    height: 61,
    display: '-webkit-box',
    '-webkit-box-orient': 'vertical',
    '-webkit-line-clamp': 2,
    overflow: 'hidden',
  },
  objectLabel: {
    height: 45,
    paddingTop: 15,
  },
  contentDummy: {
    width: '100%',
    height: 120,
    overflow: 'hidden',
    marginTop: 15,
  },
  placeholderHeader: {
    display: 'inline-block',
    height: '.8em',
    backgroundColor: theme.palette.grey?.[700],
  },
  placeholderHeaderDark: {
    display: 'inline-block',
    height: '.8em',
    backgroundColor: theme.palette.grey?.[800],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
}));

const IncidentCardFragment = graphql`
  fragment IncidentCard_node on Incident {
    id
    name
    description
    created
    modified
    objectMarking {
      edges {
        node {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
      }
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
  }
`;
interface IncidentCardProps {
  node: IncidentCard_node$key;
  onLabelClick: () => void;
}
export const IncidentCard: FunctionComponent<IncidentCardProps> = ({
  node,
  onLabelClick,
}) => {
  const classes = useStyles();
  const { t, fsd } = useFormatter();
  const data = useFragment(IncidentCardFragment, node);
  return (
    <Card classes={{ root: classes.card }} variant="outlined">
      <CardActionArea
        classes={{ root: classes.area }}
        component={Link}
        to={`/dashboard/events/incidents/${data.id}`}
      >
        <CardHeader
          classes={{ root: classes.header }}
          avatar={
            <Avatar className={classes.avatar}>{data.name.charAt(0)}</Avatar>
          }
          title={data.name}
          subheader={`${t('Updated the')} ${fsd(data.modified)}`}
          action={
            <Fire
              className={classes.icon}
              style={{ color: itemColor('Incident') }}
            />
          }
        />
        <CardContent className={classes.content}>
          <div className={classes.description}>
            <Markdown
              remarkPlugins={[remarkGfm, remarkParse]}
            >
              {data.description ?? ''}
            </Markdown>
          </div>
          <div className={classes.objectLabel}>
            <StixCoreObjectLabels
              labels={data.objectLabel}
              onClick={onLabelClick.bind(this)}
            />
          </div>
        </CardContent>
      </CardActionArea>
    </Card>
  );
};

export const IncidentCardDummy = () => {
  const classes = useStyles();
  return (
    <Card classes={{ root: classes.cardDummy }} variant="outlined">
      <CardActionArea classes={{ root: classes.area }}>
        <CardHeader
          classes={{ root: classes.header }}
          avatar={
            <Skeleton
              animation="wave"
              variant="circular"
              width={30}
              height={30}
            />
          }
          title={
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              style={{ marginBottom: 10 }}
            />
          }
          titleTypographyProps={{ color: 'inherit' }}
          subheader={
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              style={{ marginBottom: 10 }}
            />
          }
          action={
            <Skeleton
              animation="wave"
              variant="circular"
              width={30}
              height={30}
            />
          }
        />
        <CardContent classes={{ root: classes.contentDummy }}>
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="90%"
            style={{ marginBottom: 10 }}
          />
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="95%"
            style={{ marginBottom: 10 }}
          />
          <Skeleton
            animation="wave"
            variant="rectangular"
            width="90%"
            style={{ marginBottom: 10 }}
          />
        </CardContent>
      </CardActionArea>
    </Card>
  );
};
