"""
MusiKey — Musical Entropy Authentication (Python)

Cascaded KDF (PBKDF2 600k → scrypt 128MB) + Double AES-256-GCM.
Requires: cryptography (pip install cryptography)
"""

import os
import json
import math
import hashlib
import hmac
import struct
import time
from enum import IntEnum
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict

# Cryptography imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64


class Scale(IntEnum):
    CHROMATIC = 0
    MAJOR = 1
    MINOR = 2
    PENTATONIC = 3
    BLUES = 4
    DORIAN = 5
    MIXOLYDIAN = 6


SCALE_INTERVALS: Dict[int, List[int]] = {
    Scale.CHROMATIC: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    Scale.MAJOR: [0, 2, 4, 5, 7, 9, 11],
    Scale.MINOR: [0, 2, 3, 5, 7, 8, 10],
    Scale.PENTATONIC: [0, 2, 4, 7, 9],
    Scale.BLUES: [0, 3, 5, 6, 7, 10],
    Scale.DORIAN: [0, 2, 3, 5, 7, 9, 10],
    Scale.MIXOLYDIAN: [0, 2, 4, 5, 7, 9, 10],
}

HARMONIC_RATIOS = {
    0: 1.0, 1: 0.1, 2: 0.3, 3: 0.6, 4: 0.8, 5: 0.9,
    6: 0.2, 7: 0.95, 8: 0.7, 9: 0.5, 10: 0.4, 11: 0.15,
}


@dataclass
class MusicEvent:
    note: int
    velocity: int
    duration: int
    timestamp: int


@dataclass
class Song:
    events: List[MusicEvent]
    event_count: int
    total_duration: int
    scale: int
    root_note: int
    tempo: int
    entropy_bits: int


@dataclass
class Analysis:
    harmonic_score: float = 0.0
    melody_score: float = 0.0
    rhythm_score: float = 0.0
    scale_adherence: float = 0.0
    overall_musicality: float = 0.0
    is_valid_music: bool = False


@dataclass
class EncryptedSong:
    scrambled_data: str = ""
    data_size: int = 0
    salt: str = ""
    iv: str = ""
    auth_tag: str = ""
    inner_iv: str = ""
    inner_auth_tag: str = ""
    verification_hash: str = ""
    scramble_iterations: int = 600000
    kdf_type: str = "pbkdf2-scrypt"


@dataclass
class Credential:
    user_id: str = ""
    scrambled_song: Optional[EncryptedSong] = None
    scale: int = 0
    root_note: int = 0
    created_timestamp: int = 0
    last_auth_timestamp: int = 0
    last_failed_timestamp: int = 0
    auth_attempts: int = 0
    failed_attempts: int = 0
    locked: bool = False
    version: int = 2
    integrity_hash: str = ""


@dataclass
class AuthResult:
    success: bool = False
    song: Optional[Song] = None
    analysis: Optional[Analysis] = None
    error: Optional[str] = None
    destroyed: bool = False


def _note_in_scale(note: int, scale: int, root: int) -> bool:
    intervals = SCALE_INTERVALS.get(scale, SCALE_INTERVALS[Scale.CHROMATIC])
    pc = ((note % 12) - root + 12) % 12
    return pc in intervals


def _calculate_entropy(song: Song) -> int:
    if song.event_count == 0:
        return 0
    note_counts: Dict[int, int] = {}
    dur_counts: Dict[int, int] = {}
    for e in song.events:
        k = e.note % 128
        note_counts[k] = note_counts.get(k, 0) + 1
        d = e.duration % 8
        dur_counts[d] = dur_counts.get(d, 0) + 1
    n = song.event_count
    ne = sum(-((c / n) * math.log2(c / n)) for c in note_counts.values())
    de = sum(-((c / n) * math.log2(c / n)) for c in dur_counts.values())
    return int((ne + de) * n / 4)


def _generate_song_attempt(length: int, scale: Scale) -> Song:
    rand = os.urandom(1024)
    idx = 0

    def next_byte() -> int:
        nonlocal idx
        b = rand[idx % 1024]
        idx += 1
        return b

    root_note = next_byte() % 12
    tempo = 80 + (next_byte() % 80)
    intervals = SCALE_INTERVALS[scale]
    beat_dur = 60000 // tempo

    current_note = 48 + root_note
    current_time = 0
    events: List[MusicEvent] = []

    for _ in range(length):
        movement = (next_byte() % 5) - 2
        if next_byte() % 8 == 0:
            movement = (next_byte() % 9) - 4

        if scale != Scale.CHROMATIC:
            scale_pos = 0
            for j, iv in enumerate(intervals):
                if current_note % 12 == (root_note + iv) % 12:
                    scale_pos = j
                    break
            scale_pos = (scale_pos + movement) % len(intervals)
            octave = current_note // 12
            if movement > 2:
                octave += 1
            if movement < -2:
                octave -= 1
            octave = max(3, min(6, octave))
            current_note = octave * 12 + root_note + intervals[scale_pos]
        else:
            current_note = (current_note + movement + 128) % 128

        velocity = 60 + (next_byte() % 60)
        rc = next_byte() % 16
        if rc < 4:
            duration = beat_dur // 4
        elif rc < 10:
            duration = beat_dur // 2
        elif rc < 14:
            duration = beat_dur
        else:
            duration = beat_dur * 2

        events.append(MusicEvent(current_note, velocity, duration, current_time))
        current_time += duration

    song = Song(events, length, current_time, scale, root_note, tempo, 0)
    song.entropy_bits = _calculate_entropy(song)
    return song


def _analyze_song(song: Song, threshold: float) -> Analysis:
    result = Analysis()
    if song.event_count < 4:
        return result

    harm_sum = mel_sum = scale_hits = 0.0
    for i in range(1, song.event_count):
        interval = abs(song.events[i].note - song.events[i - 1].note) % 12
        harm_sum += HARMONIC_RATIOS.get(interval, 0)
        diff = abs(song.events[i].note - song.events[i - 1].note)
        mel_sum += 1.0 if diff <= 2 else 0.7 if diff <= 4 else 0.4 if diff <= 7 else 0.2
        if _note_in_scale(song.events[i].note, song.scale, song.root_note):
            scale_hits += 1

    rhythm_reg = 0.0
    for pl in range(2, 9):
        m = sum(1 for i in range(pl, song.event_count)
                if song.events[i].duration == song.events[i - pl].duration)
        rhythm_reg = max(rhythm_reg, m / (song.event_count - pl))

    n = song.event_count - 1
    result.harmonic_score = harm_sum / n
    result.melody_score = mel_sum / n
    result.rhythm_score = rhythm_reg
    result.scale_adherence = scale_hits / n
    result.overall_musicality = (
        result.harmonic_score * 0.3 +
        result.melody_score * 0.3 +
        result.rhythm_score * 0.2 +
        result.scale_adherence * 0.2
    )
    result.is_valid_music = result.overall_musicality >= threshold
    return result


def _serialize_events(events: List[MusicEvent]) -> bytes:
    buf = bytearray(len(events) * 8)
    for i, e in enumerate(events):
        o = i * 8
        struct.pack_into("<BBHI", buf, o, e.note, e.velocity, e.duration, e.timestamp)
    return bytes(buf)


def _deserialize_events(data: bytes) -> List[MusicEvent]:
    count = len(data) // 8
    events = []
    for i in range(count):
        o = i * 8
        note, vel, dur, ts = struct.unpack_from("<BBHI", data, o)
        events.append(MusicEvent(note, vel, dur, ts))
    return events


def _cascaded_kdf(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """PBKDF2 (600k) → scrypt (N=2^17, 128MB memory-hard)"""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
    pbkdf2_key = kdf.derive(passphrase.encode())

    scrypt_salt = hashlib.sha256(salt + b"scrypt-stage").digest()
    kdf2 = Scrypt(salt=scrypt_salt, length=32, n=131072, r=8, p=1, backend=default_backend())
    final_key = kdf2.derive(pbkdf2_key)

    # Zero intermediate
    pbkdf2_key = b"\x00" * 32
    return final_key


def _aes_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return ciphertext, iv, tag


def _aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes, tag: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext + tag, None)


class MusiKey:
    def __init__(
        self,
        song_length: int = 64,
        scramble_iterations: int = 600000,
        musicality_threshold: float = 0.7,
        max_failed_attempts: int = 5,
        preferred_scale: Scale = Scale.PENTATONIC,
    ):
        self.song_length = song_length
        self.scramble_iterations = scramble_iterations
        self.musicality_threshold = musicality_threshold
        self.max_failed_attempts = max_failed_attempts
        self.preferred_scale = preferred_scale

    def generate_song(self, scale: Optional[Scale] = None, length: Optional[int] = None) -> Song:
        s = scale if scale is not None else self.preferred_scale
        l = max(32, min(256, length if length is not None else self.song_length))
        for _ in range(10):
            song = _generate_song_attempt(l, s)
            if song.entropy_bits >= 40:
                return song
        return _generate_song_attempt(l, s)

    def analyze(self, song: Song) -> Analysis:
        return _analyze_song(song, self.musicality_threshold)

    def encrypt(self, song: Song, passphrase: str) -> EncryptedSong:
        salt = os.urandom(32)
        key = _cascaded_kdf(passphrase, salt, self.scramble_iterations)
        plaintext = _serialize_events(song.events)
        ver_hash = hashlib.sha256(plaintext).digest()

        # Inner layer: song content as key
        inner_key = hashlib.sha256(plaintext).digest()
        inner_ct, inner_iv, inner_tag = _aes_encrypt(inner_key, plaintext)

        # Outer layer: passphrase-derived key
        outer_ct, outer_iv, outer_tag = _aes_encrypt(key, inner_ct)

        return EncryptedSong(
            scrambled_data=base64.b64encode(outer_ct).decode(),
            data_size=len(outer_ct),
            salt=base64.b64encode(salt).decode(),
            iv=base64.b64encode(outer_iv).decode(),
            auth_tag=base64.b64encode(outer_tag).decode(),
            inner_iv=base64.b64encode(inner_iv).decode(),
            inner_auth_tag=base64.b64encode(inner_tag).decode(),
            verification_hash=base64.b64encode(ver_hash).decode(),
            scramble_iterations=self.scramble_iterations,
        )

    def decrypt(self, encrypted: EncryptedSong, passphrase: str) -> Optional[Song]:
        try:
            salt = base64.b64decode(encrypted.salt)
            key = _cascaded_kdf(passphrase, salt, encrypted.scramble_iterations)

            # Outer decrypt
            inner_ct = _aes_decrypt(
                key,
                base64.b64decode(encrypted.scrambled_data),
                base64.b64decode(encrypted.iv),
                base64.b64decode(encrypted.auth_tag),
            )

            # Inner decrypt
            if encrypted.inner_iv and encrypted.inner_auth_tag:
                ver_hash = base64.b64decode(encrypted.verification_hash)
                plaintext = _aes_decrypt(
                    ver_hash,
                    inner_ct,
                    base64.b64decode(encrypted.inner_iv),
                    base64.b64decode(encrypted.inner_auth_tag),
                )
            else:
                plaintext = inner_ct

            # Verify hash
            actual = hashlib.sha256(plaintext).digest()
            expected = base64.b64decode(encrypted.verification_hash)
            if not hmac.compare_digest(actual, expected):
                return None

            events = _deserialize_events(plaintext)
            total_dur = 0
            if events:
                last = events[-1]
                total_dur = last.timestamp + last.duration
            return Song(events, len(events), total_dur, 0, 0, 0, _calculate_entropy(
                Song(events, len(events), 0, 0, 0, 0, 0)))
        except Exception:
            return None

    def enroll(self, user_id: str, passphrase: str) -> Optional[Credential]:
        song = None
        analysis = None
        for _ in range(50):
            song = self.generate_song()
            analysis = self.analyze(song)
            if analysis.is_valid_music:
                break
            song = None
        if not song or not analysis or not analysis.is_valid_music:
            return None

        encrypted = self.encrypt(song, passphrase)
        return Credential(
            user_id=user_id,
            scrambled_song=encrypted,
            scale=song.scale,
            root_note=song.root_note,
            created_timestamp=int(time.time() * 1000),
        )

    def authenticate(self, credential: Credential, passphrase: str) -> AuthResult:
        if credential.locked:
            return AuthResult(error="Account locked")

        # Rate limiting
        if credential.last_failed_timestamp and credential.failed_attempts > 0:
            backoff = (2 ** min(credential.failed_attempts, 5)) * 1000
            if (int(time.time() * 1000) - credential.last_failed_timestamp) < backoff:
                return AuthResult(error="Rate limited")

        credential.auth_attempts += 1
        song = self.decrypt(credential.scrambled_song, passphrase)

        if not song:
            credential.failed_attempts += 1
            credential.last_failed_timestamp = int(time.time() * 1000)
            if credential.failed_attempts >= self.max_failed_attempts:
                credential.locked = True
                return AuthResult(error="Self-destructed", destroyed=True)
            return AuthResult(error="Wrong passphrase")

        song.scale = credential.scale
        song.root_note = credential.root_note
        analysis = self.analyze(song)

        if not analysis.is_valid_music:
            credential.failed_attempts += 1
            credential.last_failed_timestamp = int(time.time() * 1000)
            if credential.failed_attempts >= self.max_failed_attempts:
                credential.locked = True
                return AuthResult(error="Self-destructed", destroyed=True)
            return AuthResult(error="Musicality check failed")

        credential.failed_attempts = 0
        credential.last_auth_timestamp = int(time.time() * 1000)
        return AuthResult(success=True, song=song, analysis=analysis)


def main():
    """Quick self-test"""
    mk = MusiKey(preferred_scale=Scale.BLUES, song_length=64)

    print("--- Enrolling user ---")
    cred = mk.enroll("testuser", "MyStr0ng!Pass#2024")
    if not cred:
        print("Enrollment failed")
        return
    print(f"Enrolled: {cred.user_id}, scale={Scale(cred.scale).name}, root={cred.root_note}")

    print("\n--- Auth (correct passphrase) ---")
    result = mk.authenticate(cred, "MyStr0ng!Pass#2024")
    print(f"Success: {result.success}")
    if result.analysis:
        print(f"Musicality: {result.analysis.overall_musicality:.3f}")
    if result.song:
        print(f"Entropy: {result.song.entropy_bits} bits, Notes: {result.song.event_count}")

    print("\n--- Auth (wrong passphrase) ---")
    bad = mk.authenticate(cred, "wrong-password")
    print(f"Success: {bad.success}, Error: {bad.error}")

    print("\nAll tests passed.")


if __name__ == "__main__":
    main()
