#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import { MusiKey, Scale, Credential } from 'musikey-core';

const STORE_FILE = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.musikey-credentials.json');
const mk = new MusiKey({ preferredScale: Scale.PENTATONIC, songLength: 64 });

function loadStore(): Record<string, Credential> {
  try { return JSON.parse(fs.readFileSync(STORE_FILE, 'utf-8')); }
  catch { return {}; }
}

function saveStore(store: Record<string, Credential>): void {
  fs.writeFileSync(STORE_FILE, JSON.stringify(store, null, 2), { mode: 0o600 });
}

function prompt(question: string, hidden = false): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    if (hidden && process.stdin.isTTY) {
      process.stdout.write(question);
      const stdin = process.stdin;
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding('utf8');
      let input = '';
      const onData = (ch: string) => {
        if (ch === '\n' || ch === '\r' || ch === '\u0004') {
          stdin.setRawMode(false);
          stdin.removeListener('data', onData);
          process.stdout.write('\n');
          rl.close();
          resolve(input);
        } else if (ch === '\u0003') {
          process.exit(0);
        } else if (ch === '\u007f' || ch === '\b') {
          if (input.length > 0) { input = input.slice(0, -1); process.stdout.write('\b \b'); }
        } else {
          input += ch;
          process.stdout.write('*');
        }
      };
      stdin.on('data', onData);
    } else {
      rl.question(question, (answer) => { rl.close(); resolve(answer); });
    }
  });
}

function printHelp(): void {
  console.log(`
MusiKey CLI — Musical Entropy Authentication

Usage:
  musikey enroll <userId>       Enroll a new user with a passphrase
  musikey auth <userId>         Authenticate a user
  musikey list                  List enrolled users
  musikey delete <userId>       Delete a user credential
  musikey export <userId>       Export credential as JSON
  musikey import <file>         Import credential from JSON file
  musikey generate              Generate and display a song
  musikey help                  Show this help

Security:
  • Cascaded KDF: PBKDF2 (600k) → scrypt (128MB memory-hard)
  • Double AES-256-GCM encryption
  • Exponential backoff rate limiting
  • Self-destruct after 5 failed attempts
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0]?.toLowerCase();

  if (!command || command === 'help' || command === '--help') {
    printHelp();
    return;
  }

  const store = loadStore();

  switch (command) {
    case 'enroll': {
      const userId = args[1];
      if (!userId) { console.error('Usage: musikey enroll <userId>'); process.exit(1); }
      if (store[userId]) { console.error(`User "${userId}" already enrolled.`); process.exit(1); }

      const pass = await prompt('Passphrase: ', true);
      if (pass.length < 12) { console.error('Passphrase must be at least 12 characters.'); process.exit(1); }
      const confirm = await prompt('Confirm passphrase: ', true);
      if (pass !== confirm) { console.error('Passphrases do not match.'); process.exit(1); }

      console.log('Enrolling (this takes a few seconds due to KDF)...');
      const cred = mk.enroll(userId, pass);
      if (!cred) { console.error('Enrollment failed — could not generate valid song.'); process.exit(1); }

      store[userId] = cred;
      saveStore(store);
      console.log(`Enrolled "${userId}" — scale=${Scale[cred.scale]}, root=${cred.rootNote}`);
      break;
    }

    case 'auth':
    case 'authenticate': {
      const userId = args[1];
      if (!userId) { console.error('Usage: musikey auth <userId>'); process.exit(1); }
      const cred = store[userId];
      if (!cred) { console.error(`User "${userId}" not found.`); process.exit(1); }

      const pass = await prompt('Passphrase: ', true);
      console.log('Authenticating...');
      const result = mk.authenticate(cred, pass);
      saveStore(store);

      if (result.destroyed) {
        delete store[userId];
        saveStore(store);
        console.error('CREDENTIAL DESTROYED — too many failed attempts.');
        process.exit(1);
      }

      if (result.success) {
        console.log(`Authenticated! Musicality: ${result.analysis!.overallMusicality.toFixed(3)}, Entropy: ${result.song!.entropyBits} bits`);
      } else {
        console.error(`Failed: ${result.error}`);
        if (cred.failedAttempts > 0) console.error(`  Failed attempts: ${cred.failedAttempts}/${mk['config'].maxFailedAttempts}`);
        process.exit(1);
      }
      break;
    }

    case 'list': {
      const users = Object.keys(store);
      if (users.length === 0) { console.log('No enrolled users.'); return; }
      console.log(`Enrolled users (${users.length}):`);
      for (const u of users) {
        const c = store[u];
        console.log(`  ${u} — scale=${Scale[c.scale]}, attempts=${c.authAttempts}, locked=${c.locked}`);
      }
      break;
    }

    case 'delete': {
      const userId = args[1];
      if (!userId) { console.error('Usage: musikey delete <userId>'); process.exit(1); }
      if (!store[userId]) { console.error(`User "${userId}" not found.`); process.exit(1); }
      delete store[userId];
      saveStore(store);
      console.log(`Deleted "${userId}".`);
      break;
    }

    case 'export': {
      const userId = args[1];
      if (!userId) { console.error('Usage: musikey export <userId>'); process.exit(1); }
      if (!store[userId]) { console.error(`User "${userId}" not found.`); process.exit(1); }
      console.log(JSON.stringify(store[userId], null, 2));
      break;
    }

    case 'import': {
      const file = args[1];
      if (!file) { console.error('Usage: musikey import <file>'); process.exit(1); }
      const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
      if (!data.userId) { console.error('Invalid credential file — missing userId.'); process.exit(1); }
      if (data.locked) { console.error('Cannot import a locked/destroyed credential.'); process.exit(1); }
      if (data.failedAttempts >= 5) { console.error('Cannot import a credential with too many failed attempts.'); process.exit(1); }
      store[data.userId] = data;
      saveStore(store);
      console.log(`Imported "${data.userId}".`);
      break;
    }

    case 'generate': {
      const scaleName = args[1]?.toUpperCase();
      const scale = scaleName && Scale[scaleName as keyof typeof Scale] !== undefined
        ? Scale[scaleName as keyof typeof Scale] : Scale.PENTATONIC;
      const song = mk.generateSong(scale);
      const analysis = mk.analyze(song);
      console.log(`Generated song:`);
      console.log(`  Scale: ${Scale[song.scale]}, Root: ${song.rootNote}, Tempo: ${song.tempo} BPM`);
      console.log(`  Notes: ${song.eventCount}, Duration: ${song.totalDuration}ms`);
      console.log(`  Entropy: ${song.entropyBits} bits`);
      console.log(`  Musicality: ${analysis.overallMusicality.toFixed(3)} (${analysis.isValidMusic ? 'VALID' : 'INVALID'})`);
      console.log(`  Harmony: ${analysis.harmonicScore.toFixed(3)}, Melody: ${analysis.melodyScore.toFixed(3)}, Rhythm: ${analysis.rhythmScore.toFixed(3)}`);
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

main().catch((err) => { console.error(err.message); process.exit(1); });
