#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';

const cargoBin = join(homedir(), '.cargo', 'bin');
const currentPath = process.env.PATH || process.env.Path || '';
if (existsSync(cargoBin) && !currentPath.split(delimiter).includes(cargoBin)) {
  process.env.PATH = `${cargoBin}${delimiter}${currentPath}`;
  process.env.Path = process.env.PATH;
}

const args = process.argv.slice(2);
const bin = join(process.cwd(), 'node_modules', '.bin', process.platform === 'win32' ? 'tauri.cmd' : 'tauri');
const child = spawn(bin, args, { stdio: 'inherit', shell: process.platform === 'win32', env: process.env });
child.on('exit', (code) => process.exit(code ?? 0));
