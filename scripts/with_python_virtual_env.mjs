#!/usr/bin/env node

/**
 * Wrapper script to run commands within a Python virtual environment using sh.
 *
 * This allows running commands if your default shell is not POSIX-compliant,
 * if you don't want to activate the virtual environment globally, if you
 * often forget to activate it, or if you want to specify the virtual environment
 * path via an environment variable.
 *
 * Usage:
 *   ./with_python_virtual_env.mjs <command>    Run command in venv
 *   ./with_python_virtual_env.mjs              Output activation command for eval
 * 
 * Environment variables:
 *   VENV_PATH    Path to virtual environment (default: ../.python-venv)
 */

import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'

const VENV_PATH = process.env.VENV_PATH || join(process.cwd(), '..', '.python-venv')
const commandToRun = process.argv.slice(2).join(' ')
const activateScript = join(VENV_PATH, 'bin', 'activate')

if (!existsSync(activateScript)) {
  console.error(`Python virtual env activation script not found: ${activateScript}`)
  process.exit(2)
}

if (commandToRun) {
  const fullCommand = `. ${activateScript} && ${commandToRun}`
  console.log(`Running in python virtual environment: ${commandToRun}`)
  
  const child = spawn('sh', ['-c', fullCommand], { 
    stdio: 'inherit',
    cwd: process.cwd(),
    env: process.env
  })
  
  child.on('error', (error) => {
    console.error(`Failed to spawn shell: ${error.message}`)
    process.exit(1)
  })
  
  child.on('exit', (code) => {
    process.exit(code ?? 0)
  })
} else {
  // No command provided: output activation command for manual eval
  console.log(`. ${activateScript}`)
}