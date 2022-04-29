const IntegrityRunner = require("../checkIntegrity").default
const path = require("path")
const fs = require("fs")


describe("Verifying vsac", () => {
  const runner = new IntegrityRunner()
  const vsacConfig = JSON.parse(fs.readFileSync(path.join(__dirname, "./vsac.json")))
  for(const test of vsacConfig.tests) {
    runner.runCheck({config:test})
  }
})
