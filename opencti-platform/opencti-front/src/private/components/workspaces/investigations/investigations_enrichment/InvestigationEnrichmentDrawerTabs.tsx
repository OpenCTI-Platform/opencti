import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import { InvestigationWorkSorted } from './investigation-enrichment.types';

export type TabList = 'toreview' | 'ongoing' | 'done';

interface InvestigationEnrichmentDrawerTabsProps {
  current: TabList;
  onChange: (tab: TabList) => void;
  works: InvestigationWorkSorted;
}

const InvestigationEnrichmentDrawerTabs = ({
  current,
  onChange,
  works,
}: InvestigationEnrichmentDrawerTabsProps) => {
  const { t_i18n } = useFormatter();

  const doneSize = [...works.done.values()].flat().length;
  const ongoingSize = [...works.ongoing.values()].flat().length;

  return (
    <Tabs value={current}>
      <TabsList>
        <TabsTrigger
          disabled
          value="to-review"
          onClick={() => onChange('toreview')}
        >
          {t_i18n('To review')} (0)
        </TabsTrigger>
        <TabsTrigger
          value="ongoing"
          onClick={() => onChange('ongoing')}
        >
          {t_i18n('Ongoing')} ({ongoingSize})
        </TabsTrigger>
        <TabsTrigger
          value="done"
          onClick={() => onChange('done')}
        >
          {t_i18n('Done')} ({doneSize})
        </TabsTrigger>
      </TabsList>
    </Tabs>
  );
};

export default InvestigationEnrichmentDrawerTabs;
