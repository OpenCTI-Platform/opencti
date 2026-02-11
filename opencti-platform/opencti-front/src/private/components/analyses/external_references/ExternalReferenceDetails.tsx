import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { OpenInBrowserOutlined } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Tooltip from '@mui/material/Tooltip';
import { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import { useFormatter } from '../../../../components/i18n';
import ItemCreators from '../../../../components/ItemCreators';
import { EMPTY_VALUE } from '../../../../utils/String';
import { ExternalReferenceDetails_externalReference$data } from './__generated__/ExternalReferenceDetails_externalReference.graphql';

interface ExternalReferenceDetailsComponentProps {
  externalReference: ExternalReferenceDetails_externalReference$data;
}

const ExternalReferenceDetailsComponent = ({
  externalReference,
}: ExternalReferenceDetailsComponentProps) => {
  const { t_i18n } = useFormatter();
  const [displayExternalLink, setDisplayExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState<string | URL | undefined>(
    undefined,
  );
  const handleOpenExternalLink = (url: string) => {
    setDisplayExternalLink(true);
    setExternalLink(url);
  };

  const handleCloseExternalLink = () => {
    setDisplayExternalLink(false);
    setExternalLink(undefined);
  };

  const handleBrowseExternalLink = () => {
    window.open(externalLink, '_blank');
    setDisplayExternalLink(false);
    setExternalLink(undefined);
  };

  return (
    <div style={{ height: '100%' }}>
      <Card
        title={t_i18n('Details')}
        sx={{
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
        }}
      >
        <div>
          <Label>
            {t_i18n('External ID')}
          </Label>
          <span>{externalReference.external_id ?? EMPTY_VALUE}</span>
        </div>

        <div>
          <Label action={(
            <Tooltip title={t_i18n('Browse the link')}>
              <IconButton
                onClick={() => handleOpenExternalLink(externalReference.url ?? '')}
                color="primary"
                disabled={!externalReference.url}
              >
                <OpenInBrowserOutlined />
              </IconButton>
            </Tooltip>
          )}
          >
            {t_i18n('URL')}
          </Label>
          {
            externalReference.url
              ? <pre style={{ minHeight: 35 }}>{externalReference.url}</pre>
              : <span>{EMPTY_VALUE}</span>
          }
        </div>

        <div>
          <Label>{t_i18n('Creators')}</Label>
          <ItemCreators creators={externalReference.creators ?? []} />
        </div>
      </Card>

      <Dialog
        open={displayExternalLink}
        onClose={handleCloseExternalLink}
        title={t_i18n('Are you sure?')}
        size="small"
      >
        <DialogContentText>
          {t_i18n('Do you want to browse this external link?')}
        </DialogContentText>
        <DialogActions>
          <Button variant="secondary" onClick={handleCloseExternalLink}>{t_i18n('Cancel')}</Button>
          <Button onClick={handleBrowseExternalLink}>
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

const ExternalReferenceDetails = createFragmentContainer(
  ExternalReferenceDetailsComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceDetails_externalReference on ExternalReference {
        id
        external_id
        url
        creators {
          id
          name
        }
      }
    `,
  },
);

export default ExternalReferenceDetails;
