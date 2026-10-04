import { Link, useNavigate } from 'react-router';
import { Hero, HeroBody, HeroHeader, Text } from '@filigran/design-system';
import AutoFixHighOutlined from '@mui/icons-material/AutoFixHighOutlined';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import { CURATION_DOCUMENTATION_URL, CURATION_SETTINGS_PATH } from './curationUtils';

interface CurationFirstUseProps {
  title: string;
  description: string;
  /** When the next run that fills the surface is due, or null when curation is turned off. */
  nextRunDate: string | null | undefined;
  testId: string;
}

/** First-use state of a curation surface: what fills it, when, and where to act. */
const CurationFirstUse = ({ title, description, nextRunDate, testId }: CurationFirstUseProps) => {
  const { t_i18n, rd, fldt } = useFormatter();
  const navigate = useNavigate();
  const isGrantedToSettings = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const schedule = nextRunDate
    ? t_i18n('The next run is due {relative} ({date}).', { values: { relative: rd(nextRunDate), date: fldt(nextRunDate) } })
    : t_i18n('Curation is turned off, so nothing is scheduled.');
  return (
    <Hero data-testid={testId}>
      <HeroHeader
        icon={<AutoFixHighOutlined color="primary" />}
        action={isGrantedToSettings ? (
          <Button onClick={() => navigate(CURATION_SETTINGS_PATH)}>{t_i18n('Open the curation settings')}</Button>
        ) : undefined}
      >
        <Text as="h2" variant="title-sm">{title}</Text>
      </HeroHeader>
      <HeroBody>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          <Text as="p" variant="content-base">{description}</Text>
          <Text as="p" variant="content-base-medium" data-testid={`${testId}-schedule`}>{schedule}</Text>
          {!isGrantedToSettings && (
            <Text as="p" variant="content-base">{t_i18n('To change what curation covers or when it runs, ask your administrator.')}</Text>
          )}
          <Link to={CURATION_DOCUMENTATION_URL} target="_blank" rel="noopener noreferrer">
            {t_i18n('Read the documentation')}
          </Link>
        </Box>
      </HeroBody>
    </Hero>
  );
};

export default CurationFirstUse;
