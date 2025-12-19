import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Slide from '@mui/material/Slide';
import IconButton from '@common/button/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { VisibilityOutlined } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import { stixDomainObjectsLinesSearchQuery } from './StixDomainObjectsLines';
import { fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import { resolveLink } from '../../../../utils/Entity';
import ItemMarkings from '../../../../components/ItemMarkings';

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
      if (this.props.value.length >= 2) {
        fetchQuery(stixDomainObjectsLinesSearchQuery, {
          types: this.props.types,
          search: `"${this.props.value}"`,
          count: 10,
        })
          .toPromise()
          .then((data) => {
            const potentialDuplicates = data.stixDomainObjects?.edges ?? [];
            this.setState({ potentialDuplicates });
          });
      } else {
        this.setState({ potentialDuplicates: [] });
      }
    }
  }

  handleOpen(e) {
    this.setState({ open: true });
    e.preventDefault();
  }

  handleClose() {
    this.setState({ open: false });
  }

  render() {
    const { potentialDuplicates } = this.state;
    const { t, classes, value } = this.props;
    return (
      <span
        className={
          potentialDuplicates.length > 0
            ? classes.duplicates
            : classes.noDuplicate
        }
      >
        {value && potentialDuplicates.length === 0
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
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.open}
          fullWidth={true}
          maxWidth="md"
          keepMounted={true}
          slots={{ transition: Transition }}
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
                    <ListItem
                      key={element.node.id}
                      dense={true}
                      divider={true}
                      secondaryAction={(
                        <IconButton
                          component={Link}
                          to={`${link}/${element.node.id}`}
                        >
                          <VisibilityOutlined />
                        </IconButton>
                      )}
                    >
                      <ListItemIcon>
                        <ItemIcon type={element.node.entity_type} />
                      </ListItemIcon>
                      <ListItemText
                        primary={element.node.name}
                        secondary={truncate(element.node.description, 60)}
                      />
                      <div style={{ marginRight: 50 }}>
                        {element.node.createdBy?.name ?? '-'}
                      </div>
                      <div style={{ marginRight: 50 }}>
                        <ItemMarkings
                          variant="inList"
                          markingDefinitions={element.node.objectMarking ?? []}
                        />
                      </div>
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
