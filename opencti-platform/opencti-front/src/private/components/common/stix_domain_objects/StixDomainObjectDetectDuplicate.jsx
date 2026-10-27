import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { VisibilityOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import * as PropTypes from 'prop-types';
import { Component } from 'react';
import { Link } from 'react-router';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { fetchQuery } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import { EMPTY_VALUE, truncate } from '../../../../utils/String';
import { stixDomainObjectsLinesSearchQuery } from './StixDomainObjectsLines';

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
    const { t, value } = this.props;
    return (
      <Box
        component="span"
        sx={{ color: potentialDuplicates.length > 0 ? '#ff9800' : '#4caf50' }}
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
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          title={t('Potential duplicate entities')}
        >
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
                      aria-label={t('Go to')}
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
                    {element.node.createdBy?.name ?? EMPTY_VALUE}
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
        </Dialog>
      </Box>
    );
  }
}

StixDomainObjectDetectDuplicate.propTypes = {
  types: PropTypes.array,
  value: PropTypes.string,
  t: PropTypes.func,
};

export default inject18n(StixDomainObjectDetectDuplicate);
