import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import Slide from '@material-ui/core/Slide';
import IconButton from '@material-ui/core/IconButton';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { VisibilityOutlined } from '@material-ui/icons';
import { Link } from 'react-router-dom';
import { stixDomainObjectsLinesSearchQuery } from './StixDomainObjectsLines';
import { fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import ItemMarking from '../../../../components/ItemMarking';
import { resolveLink } from '../../../../utils/Entity';

const styles = () => ({
  dialogPaper: {
    maxHeight: '60vh',
  },
  noDuplicate: {
    color: '#4caf50',
  },
  duplicates: {
    color: '#ff9800',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class StixDomainObjectDetectDuplicate extends Component {
  constructor(props) {
    super(props);
    this.state = {
      potentialDuplicates: [],
      open: false,
    };
  }

  componentDidUpdate(prevProps) {
    if (this.props.value !== prevProps.value) {
      if (this.props.value.length > 2) {
        fetchQuery(stixDomainObjectsLinesSearchQuery, {
          types: this.props.types,
          search: `"${this.props.value}"`,
          count: 10,
        })
          .toPromise()
          .then((data) => {
            const potentialDuplicates = pathOr(
              [],
              ['stixDomainObjects', 'edges'],
              data,
            );
            this.setState({ potentialDuplicates });
          });
      } else {
        this.setState({ potentialDuplicates: [] });
      }
    }
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  render() {
    const { potentialDuplicates } = this.state;
    const { t, classes } = this.props;
    return (
      <span
        className={
          potentialDuplicates.length > 0
            ? classes.duplicates
            : classes.noDuplicate
        }
      >
        {potentialDuplicates.length === 0
          ? t('No potential duplicate entities has been found.')
          : ''}
        {potentialDuplicates.length === 1 ? (
          <span>
            <a href="# " onClick={this.handleOpen.bind(this)}>
              1 {t('potential duplicate entity')}
            </a>{' '}
            {t('has been found.')}
          </span>
        ) : (
          ''
        )}
        {potentialDuplicates.length > 1 ? (
          <span>
            <a href="# " onClick={this.handleOpen.bind(this)}>
              {potentialDuplicates.length} {t('potential duplicate entities')}
            </a>{' '}
            {t('have been found.')}
          </span>
        ) : (
          ''
        )}
        <Dialog
          open={this.state.open}
          fullWidth={true}
          maxWidth="md"
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleClose.bind(this)}
          classes={{ paper: classes.dialogPaper }}
        >
          <DialogTitle>{t('Potential duplicate entities')}</DialogTitle>
          <DialogContent dividers={true}>
            <div className={classes.container}>
              <List>
                {potentialDuplicates.map((element) => {
                  const link = resolveLink(element.node.entity_type);
                  return (
                    <ListItem key={element.node.id} dense={true} divider={true}>
                      <ListItemIcon>
                        <ItemIcon type={element.node.entity_type} />
                      </ListItemIcon>
                      <ListItemText
                        primary={element.node.name}
                        secondary={truncate(element.node.description, 60)}
                      />
                      <div style={{ marginRight: 50 }}>
                        {pathOr(
                          '',
                          ['node', 'createdBy', 'node', 'name'],
                          element,
                        )}
                      </div>
                      <div style={{ marginRight: 50 }}>
                        {pathOr(
                          [],
                          ['node', 'markingDefinitions', 'edges'],
                          element,
                        ).length > 0 ? (
                            map(
                              (markingDefinition) => (
                              <ItemMarking
                                key={markingDefinition.node.id}
                                label={markingDefinition.node.definition}
                                color={markingDefinition.node.x_opencti_color}
                                variant="inList"
                              />
                              ),
                              element.node.objectMarking.edges,
                            )
                          ) : (
                          <ItemMarking label="TLP:WHITE" variant="inList" />
                          )}
                      </div>
                      <ListItemSecondaryAction>
                        <IconButton
                          component={Link}
                          to={`${link}/${element.node.id}`}
                        >
                          <VisibilityOutlined />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                  );
                })}
              </List>
            </div>
          </DialogContent>
        </Dialog>
      </span>
    );
  }
}

StixDomainObjectDetectDuplicate.propTypes = {
  types: PropTypes.array,
  value: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectDetectDuplicate);
