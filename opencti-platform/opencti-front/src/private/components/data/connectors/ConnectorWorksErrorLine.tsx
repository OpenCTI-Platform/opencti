import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import Button from '@mui/material/Button';
import React, { FunctionComponent, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import IconButton from '@mui/material/IconButton';
import { InfoOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { ParsedWorkMessage, ResolvedEntity } from '@components/data/connectors/parseWorkErrors';
import ItemCopy from '../../../../components/ItemCopy';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import Typography from '@mui/material/Typography';
import ItemEntityType from '../../../../components/ItemEntityType';

interface ConnectorWorksErrorLineProps {
  error: ParsedWorkMessage;
}

const ConnectorWorksErrorLine: FunctionComponent<ConnectorWorksErrorLineProps> = ({ error }) => {
  const { t_i18n, nsdt } = useFormatter();
  const [openModalErrorDetails, setOpenModalErrorDetails] = useState<boolean>(false);
  const truncateLimit = 80;

  const handleToggleModalError = () => {
    setOpenModalErrorDetails(!openModalErrorDetails);
  };

  if (!error.rawError) {
    return null;
  }

  const entityListItem = (entity: ResolvedEntity, label: string) => {
    const name = ` ${entity.representative?.main ?? 'Unknown'}`;
    return (
      <ListItem disableGutters={true}>
        <div>
          <Typography variant="h3" gutterBottom={true}>{t_i18n(label)}</Typography>
          {entity.entity_type ? (
            <Tooltip title={name}>
              <a href={`/dashboard/id/${entity.id}`} target="_blank" rel="noreferrer">
                [{entity.entity_type}] {truncate(name, truncateLimit)}
              </a>
            </Tooltip>
          ) : (
            <div>{name}</div>
          )}
        </div>
      </ListItem>
    );
  };

  return (
    <>
      <TableRow key={error.rawError.timestamp}>
        <TableCell>{nsdt(error.rawError.timestamp)}</TableCell>
        <TableCell>
          {error.isParsed ? (
            <a href={`https://docs.opencti.io/latest/deployment/troubleshooting/#${error.parsedError.category}`} target="_blank" rel="noreferrer">{error.parsedError.category}</a>
          ) : (
            <a href={'https://docs.opencti.io/latest/deployment/troubleshooting'} target="_blank" rel="noreferrer">{t_i18n('Unknown')}</a>
          )}
        </TableCell>
        <TableCell>{error.isParsed ? error.parsedError.message : error.rawError.message}</TableCell>
        <TableCell>
          <List dense={true}>
            {error.isParsed ? (
              entityListItem(error.parsedError.entity, 'Entity')
            ) : (
              truncate(error.rawError.source, truncateLimit)
            )}
            {error.isParsed && error.parsedError.entity.from && (
              entityListItem(error.parsedError.entity.from, 'From')
            )}
            {error.isParsed && error.parsedError.entity.to && (
              entityListItem(error.parsedError.entity.to, 'To')
            )}
          </List>
        </TableCell>
        <TableCell>
          <Tooltip title={t_i18n('Details')}>
            <IconButton
              onClick={handleToggleModalError}
              aria-haspopup="true"
              color="primary"
            >
              <InfoOutlined />
            </IconButton>
          </Tooltip>
        </TableCell>
      </TableRow>

      <Dialog
        PaperProps={{ elevation: 1 }}
        open={openModalErrorDetails}
        TransitionComponent={Transition}
        onClose={handleToggleModalError}
      >
        <DialogTitle>{t_i18n('Error')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            <pre><ItemCopy content={error.rawError.timestamp ?? '-'} /></pre>
            <pre><ItemCopy content={error.rawError.message ?? '-'} variant={'wrap'} /></pre>
            <pre><ItemCopy content={error.rawError.source ?? '-'} variant={'wrap'} /></pre>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleToggleModalError} color="primary">
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ConnectorWorksErrorLine;
