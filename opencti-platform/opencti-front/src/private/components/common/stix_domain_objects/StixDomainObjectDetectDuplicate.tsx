import React, { FunctionComponent, useEffect, useState } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { pathOr } from 'ramda';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { Link } from 'react-router-dom';
import { VisibilityOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import Slide, { SlideProps } from '@mui/material/Slide';
import { stixDomainObjectsLinesSearchQuery } from '@components/common/stix_domain_objects/StixDomainObjectsLines';
import { StixDomainObjectsLinesSearchQuery$data } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectsLinesSearchQuery.graphql';
import { Option } from '@components/common/form/ReferenceField';
import ItemMarkings from '../../../../components/ItemMarkings';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';

const useStyles = makeStyles({
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

const Transition = React.forwardRef(({ children, ...otherProps }: SlideProps, ref) => (
  <Slide direction='up' ref={ref} {...otherProps}>{children}</Slide>
));
Transition.displayName = 'TransitionSlide';

interface StixDomainObjectDetectDuplicateProps {
  types: string[];
  value: string;
}

const StixDomainObjectDetectDuplicate: FunctionComponent<StixDomainObjectDetectDuplicateProps> = ({
  types,
  value,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [potentialDuplicates, setPotentialDuplicates] = useState<
  {
    node: {
      description: string | null;
      id: string;
      name: string;
      entity_type: string;
      objectMarking: Option[];
    };
  }[]
  >([]);
  const handleOpen = () => {
    setDialogOpen(true);
  };
  const handleClose = () => {
    setDialogOpen(false);
  };
  // Similar to componentDidMount and componentDidUpdate:
  useEffect(() => {
    if (value.length > 2) {
      fetchQuery(stixDomainObjectsLinesSearchQuery, {
        types,
        search: `"${value}"`,
        count: 10,
      })
        .toPromise()
        .then((data) => {
          const duplicates = (data as StixDomainObjectsLinesSearchQuery$data)?.stixDomainObjects?.edges ?? [];
          setPotentialDuplicates(duplicates);
        });
    } else {
      setPotentialDuplicates([]);
    }
  }, [value, types, potentialDuplicates.length]);

  return (
    <span
      className={
        potentialDuplicates.length > 0
          ? classes.duplicates
          : classes.noDuplicate
      }
    >
      {potentialDuplicates.length === 0
        ? t_i18n('No potential duplicate entities has been found.')
        : ''}
      {potentialDuplicates.length === 1 ? (
        <span>
          <a href="# " onClick={handleOpen}>
            1 {t_i18n('potential duplicate entity')}
          </a>{' '}
          {t_i18n('has been found.')}
        </span>
      ) : (
        ''
      )}
      {potentialDuplicates.length > 1 ? (
        <span>
          <a href="# " onClick={handleOpen}>
            {potentialDuplicates.length} {t_i18n('potential duplicate entities')}
          </a>{' '}
          {t_i18n('have been found.')}
        </span>
      ) : (
        ''
      )}
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={dialogOpen}
        fullWidth={true}
        maxWidth="md"
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleClose}
        classes={{ paper: classes.dialogPaper }}
      >
        <DialogTitle>{t_i18n('Potential duplicate entities')}</DialogTitle>
        <DialogContent dividers={true}>
          <div>
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
                      <ItemMarkings
                        variant="inList"
                        markingDefinitions={
                            element.node.objectMarking ?? []
                          }
                      />
                    </div>
                    <ListItemSecondaryAction>
                      <IconButton
                        component={Link}
                        to={`${link}/${element.node.id}`}
                        size="large"
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
};

export default StixDomainObjectDetectDuplicate;
