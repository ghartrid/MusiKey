import { MusiKeyWasm, Scale } from './musikey-wasm';

async function test() {
  const mk = new MusiKeyWasm({ preferredScale: Scale.BLUES, songLength: 64 });

  console.log('--- Enrolling user ---');
  const cred = await mk.enroll('testuser', 'MyStr0ng!Pass#2024');
  if (!cred) { console.error('Enrollment failed'); process.exit(1); }
  console.log(`Enrolled: ${cred.userId}, scale=${cred.scale}, root=${cred.rootNote}`);

  console.log('\n--- Auth (correct passphrase) ---');
  const result = await mk.authenticate(cred, 'MyStr0ng!Pass#2024');
  console.log(`Success: ${result.success}`);
  if (result.analysis) console.log(`Musicality: ${result.analysis.overallMusicality.toFixed(3)}`);
  if (result.song) console.log(`Entropy: ${result.song.entropyBits} bits, Notes: ${result.song.eventCount}`);

  console.log('\n--- Auth (wrong passphrase) ---');
  const bad = await mk.authenticate(cred, 'wrong-password');
  console.log(`Success: ${bad.success}, Error: ${bad.error}`);

  console.log('\nAll tests passed.');
}

test().catch(console.error);
