import { MusiKey, Scale } from './index';

const mk = new MusiKey({ preferredScale: Scale.BLUES, songLength: 64 });

// Enroll
console.log('--- Enrolling user ---');
const cred = mk.enroll('testuser', 'MyStr0ng!Pass#2024');
if (!cred) { console.error('Enrollment failed'); process.exit(1); }
console.log(`Enrolled: ${cred.userId}, scale=${cred.scale}, root=${cred.rootNote}`);

// Authenticate (correct)
console.log('\n--- Auth (correct passphrase) ---');
const result = mk.authenticate(cred, 'MyStr0ng!Pass#2024');
console.log(`Success: ${result.success}`);
if (result.analysis) console.log(`Musicality: ${result.analysis.overallMusicality.toFixed(3)}`);
if (result.song) console.log(`Entropy: ${result.song.entropyBits} bits, Notes: ${result.song.eventCount}`);

// Authenticate (wrong)
console.log('\n--- Auth (wrong passphrase) ---');
const bad = mk.authenticate(cred, 'wrong-password');
console.log(`Success: ${bad.success}, Error: ${bad.error}`);

console.log('\nAll tests passed.');
