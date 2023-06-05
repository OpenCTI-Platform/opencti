export interface RelayError {
  res: {
    errors: {
      data: {
        existingIds: string[]
        reason: string
      }
    }[]
  }
}
