export interface RelayError {
  res: {
    errors: {
      message?: string
      data: {
        existingIds: string[]
        reason: string
      }
    }[]
  }
}
