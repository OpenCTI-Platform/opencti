import type { BasicStoreBase } from './store';

interface Work extends BasicStoreBase {
  _index: string
  id: string
  sort: number[]
  internal_id: string
  timestamp: string
  name: string
  entity_type: string
  event_type: string
  event_source_id: string
  user_id: string
  connector_id: string
  status: string
  import_expected_number: number
  received_time: string | null
  processed_time: string | null
  completed_time: string | null
  completed_number: number
  messages: string[]
  errors: string[]
}
