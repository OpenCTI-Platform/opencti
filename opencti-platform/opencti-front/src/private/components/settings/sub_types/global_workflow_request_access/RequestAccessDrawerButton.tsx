import { useState } from 'react';
import { Button } from '@filigran/design-system';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../../components/i18n';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import RequestAccessSettings from './RequestAccessSettings';
import useRequestAccessConfiguration from './useRequestAccessConfiguration';

/**
 * Opens the request access workflow settings in a drawer, for the new workflow editor page
 * where the canvas takes the room the legacy card gave them.
 */
const RequestAccessDrawerButton = () => {
  const { t_i18n } = useFormatter();
  const { subType } = useSubTypeOutletContext();
  const configuration = useRequestAccessConfiguration();
  const [open, setOpen] = useState(false);

  if (!configuration) return null;

  return (
    <>
      <Button priority="secondary" size="sm" onClick={() => setOpen(true)}>
        {t_i18n('Request access workflow')}
      </Button>
      <Drawer
        title={t_i18n('Request access workflow')}
        open={open}
        onClose={() => setOpen(false)}
        size="medium"
      >
        <RequestAccessSettings data={subType} subTypeId={subType.id} dataConfiguration={configuration} />
      </Drawer>
    </>
  );
};

export default RequestAccessDrawerButton;
