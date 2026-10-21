import { Link } from 'react-router';
import { ShieldSyncOutline } from 'mdi-material-ui';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { PATH_DISSEMINATION_ASSURANCE } from './disseminationAssuranceUtils';

/** Entry to the Dissemination assurance area from the Deployments tabs; its menu entry belongs to the Defense hub. */
const DisseminationAssuranceLink = () => {
  const { t_i18n } = useFormatter();
  return (
    <Button
      variant="tertiary"
      component={Link}
      to={`${PATH_DISSEMINATION_ASSURANCE}/overview`}
      startIcon={<ShieldSyncOutline fontSize="small" />}
      data-testid="dissemination-assurance-link"
    >
      {t_i18n('Dissemination assurance')}
    </Button>
  );
};

export default DisseminationAssuranceLink;
