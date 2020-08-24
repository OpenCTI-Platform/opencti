import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, pathOr, take, propOr,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Card from '@material-ui/core/Card';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import Typography from '@material-ui/core/Typography';
import Avatar from '@material-ui/core/Avatar';
import { WorkOutlined, AccountCircleOutlined } from '@material-ui/icons';
import { ClockOutline } from 'mdi-material-ui';
import { Link } from 'react-router-dom';
import CardActionArea from '@material-ui/core/CardActionArea';
import Divider from '@material-ui/core/Divider';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: '100%',
    borderRadius: 6,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    backgroundColor: theme.palette.grey[600],
  },
  icon: {
    margin: '10px 20px 0 0',
    fontSize: 40,
    color: '#242d30',
  },
  area: {
    width: '100%',
    height: '100%',
  },
  description: {
    height: 70,
    overflow: 'hidden',
  },
  objectLabel: {
    height: 45,
    paddingTop: 7,
  },
});

class StixCoreObjectNoteCardComponent extends Component {
  render() {
    const {
      nsdt, classes, node, t,
    } = this.props;
    return (
      <Card classes={{ root: classes.card }} raised={true} variant="outlined">
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          to={`/dashboard/analysis/notes/${node.id}`}
        >
          <CardHeader
            title={
              <span>
                <AccountCircleOutlined
                  fontSize="small"
                  style={{ float: 'left', marginRight: 5 }}
                />
                <Typography variant="body2" style={{ paddingTop: 2 }}>
                  {propOr('-', 'name', node.createdBy)}
                </Typography>
              </span>
            }
            subheader={
              <div style={{ marginTop: 10 }}>
                <ClockOutline
                  fontSize="small"
                  style={{ float: 'left', marginRight: 5 }}
                />
                <Typography variant="body2" style={{ paddingTop: 2 }}>
                  {nsdt(node.created)}
                </Typography>
              </div>
            }
            action={
              <div style={{ marginTop: 20 }}>
                {take(1, pathOr([], ['objectMarking', 'edges'], node)).map(
                  (markingDefinition) => (
                    <ItemMarking
                      key={markingDefinition.node.id}
                      label={markingDefinition.node.definition}
                      color={markingDefinition.node.x_opencti_color}
                    />
                  ),
                )}
              </div>
            }
          />
          <Divider variant="light" />
          <CardContent style={{ paddingBottom: 10 }}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Abstract')}
            </Typography>
            <Typography
              variant="body2"
              noWrap={true}
              style={{ margin: '10px 0 10px 0', fontWeight: 500 }}
            >
              <Markdown className="markdown" source={node.attribute_abstract} />
            </Typography>
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Content')}
            </Typography>
            <Typography variant="body2" style={{ marginBottom: 20 }}>
              <Markdown className="markdown" source={node.content} />
            </Typography>
            <div className={classes.objectLabel}>
              <StixCoreObjectLabels labels={node.objectLabel} />
            </div>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

StixCoreObjectNoteCardComponent.propTypes = {
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
};

const StixCoreObjectNoteCard = createFragmentContainer(
  StixCoreObjectNoteCardComponent,
  {
    node: graphql`
      fragment StixCoreObjectNoteCard_node on Note {
        id
        attribute_abstract
        content
        created
        modified
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition
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
    `,
  },
);

export default compose(inject18n, withStyles(styles))(StixCoreObjectNoteCard);
