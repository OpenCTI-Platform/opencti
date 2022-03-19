import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { GraphOutline, VectorLink } from 'mdi-material-ui';
import { ViewColumnOutlined } from '@mui/icons-material';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import ExportButtons from '../../../../components/ExportButtons';

const styles = () => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  marking: {
    float: 'left',
    overflowX: 'hidden',
    marginLeft: 15,
  },
  aliases: {
    marginRight: 7,
  },
  aliasesInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
  modes: {
    margin: '-10px 0 0 0',
    float: 'right',
  },
  button: {
    marginRight: 20,
  },
  export: {
    margin: '-10px 0 0 0',
    float: 'right',
  },
});

class ContainerHeaderComponent extends Component {
  render() {
    const {
      classes,
      container,
      variant,
      PopoverComponent,
      fd,
      link,
      modes,
      currentMode,
      knowledge,
      adjust,
      t,
    } = this.props;
    return (
      <div>
        <Tooltip
          title={
            container.name
            || container.attribute_abstract
            || container.content
            || container.opinion
            || `${fd(container.first_observed)} - ${fd(container.last_observed)}`
          }
        >
          <Typography
            variant="h1"
            gutterBottom={true}
            classes={{ root: classes.title }}
          >
            {truncate(
              container.name
                || container.attribute_abstract
                || container.content
                || container.opinion
                || `${fd(container.first_observed)} - ${fd(
                  container.last_observed,
                )}`,
              80,
            )}
          </Typography>
        </Tooltip>
        {variant !== 'noMarking' && (
          <div className={classes.marking}>
            {pathOr([], ['objectMarking', 'edges'], container).map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                  color={markingDefinition.node.x_opencti_color}
                />
              ),
            )}
          </div>
        )}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <div className={classes.popover}>
            {React.cloneElement(PopoverComponent, { id: container.id })}
          </div>
        </Security>
        {knowledge && (
          <div className={classes.export}>
            <ExportButtons
              domElementId="container"
              name={t('Report representation')}
              pixelRatio={currentMode === 'graph' ? 1 : 2}
              adjust={adjust}
            />
          </div>
        )}
        {modes && (
          <div className={classes.modes}>
            {modes.includes('graph') && (
              <Tooltip title={t('Graph view')}>
                <IconButton
                  color={currentMode === 'graph' ? 'secondary' : 'primary'}
                  component={Link}
                  to={`${link}/graph`}
                  size="large"
                >
                  <GraphOutline />
                </IconButton>
              </Tooltip>
            )}
            {modes.includes('correlation') && (
              <Tooltip title={t('Correlation view')}>
                <IconButton
                  color={
                    currentMode === 'correlation' ? 'secondary' : 'primary'
                  }
                  component={Link}
                  to={`${link}/correlation`}
                  size="large"
                >
                  <VectorLink />
                </IconButton>
              </Tooltip>
            )}
            {modes.includes('matrix') && (
              <Tooltip title={t('Tactics matrix view')}>
                <IconButton
                  color={currentMode === 'matrix' ? 'secondary' : 'primary'}
                  component={Link}
                  to={`${link}/matrix`}
                  size="large"
                >
                  <ViewColumnOutlined />
                </IconButton>
              </Tooltip>
            )}
          </div>
        )}
        <div className="clearfix" />
      </div>
    );
  }
}

ContainerHeaderComponent.propTypes = {
  container: PropTypes.object,
  PopoverComponent: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  link: PropTypes.string,
  modes: PropTypes.array,
  currentMode: PropTypes.string,
  knowledge: PropTypes.bool,
  adjust: PropTypes.func,
};

const ContainerHeader = createFragmentContainer(ContainerHeaderComponent, {
  container: graphql`
    fragment ContainerHeader_container on Container {
      id
      ... on Report {
        name
      }
      ... on Note {
        attribute_abstract
        content
      }
      ... on Opinion {
        opinion
      }
      ... on ObservedData {
        name
        first_observed
        last_observed
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
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ContainerHeader);
