import { type SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import { type FilterGroup } from '../filters/filtersHelpers-types';

export interface MessageFromLocalStorage {
  id: string
  message: string
  activated: boolean
  dismissible: boolean
  updated_at: Date
  dismiss: boolean
  color: string
}
export interface LocalStorage {
  numberOfElements?: {
    number: number
    symbol: string
    original?: number
  }
  filters?: FilterGroup
  dynamicFromFilters?: FilterGroup
  dynamicToFilters?: FilterGroup
  id?: string
  searchTerm?: string
  category?: string
  toId?: string
  sortBy?: string
  orderAsc?: boolean
  openExports?: boolean
  count?: number
  types?: string[]
  view?: string
  zoom?: Record<string, unknown>
  redirectionMode?: string
  selectAll?: boolean
  selectedElements?: Record<string, unknown>
  deSelectedElements?: Record<string, unknown>
  messages?: MessageFromLocalStorage[]
  timeField?: string
  dashboard?: string
  latestAddFilterId?: string
  latestAddFilterKey?: string
  pageSize?: string
  savedFilters?: SavedFiltersSelectionData
}
