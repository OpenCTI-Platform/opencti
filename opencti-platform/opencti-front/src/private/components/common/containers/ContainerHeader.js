import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import { Link } from 'react-router-dom';
import Button from '@material-ui/core/Button';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

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
    margin: '-2px 0 0 0',
    float: 'right',
  },
  button: {
    marginRight: 20,
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
      t,
    } = this.props;
    return (
      <div>
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
        {modes && (
          <div className={classes.modes}>
            {modes.map((mode) => (mode.current ? (
                <Button
                  key={mode.key}
                  size="small"
                  variant="contained"
                  color="primary"
                  classes={{ root: classes.button }}
                >
                  {t(mode.label)}
                </Button>
            ) : (
                <Button
                  key={mode.key}
                  component={Link}
                  to={`${link}/${mode.key}`}
                  size="small"
                  variant="text"
                  color="inherit"
                  classes={{ root: classes.button }}
                >
                  {t(mode.label)}
                </Button>
            )))}
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
