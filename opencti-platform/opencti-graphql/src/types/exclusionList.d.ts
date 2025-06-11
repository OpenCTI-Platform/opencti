export interface ExclusionListCacheItem {
  id: string
  types: string[]
  values: string[]
  ranges?: number[] // only used for IPs
}
