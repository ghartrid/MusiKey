// Musical Challenge-Response MFA
// Picks a fragment of the song and asks a musical question about it

import { MusikeySong, MusikeyEvent } from './types';

export interface MusicChallenge {
  fragmentStart: number;
  fragmentEnd: number;
  fragment: MusikeyEvent[];
  question: string;
  correctAnswer: string;
  options: string[];
}

type QuestionGenerator = (fragment: MusikeyEvent[], song: MusikeySong) => { question: string; correct: string; options: string[] } | null;

const questionGenerators: QuestionGenerator[] = [
  // Direction: does the fragment go up, down, or stay?
  (fragment) => {
    if (fragment.length < 3) return null;
    const first = fragment[0].note;
    const last = fragment[fragment.length - 1].note;
    const diff = last - first;
    const correct = diff > 2 ? 'Ascending' : diff < -2 ? 'Descending' : 'Steady';
    return {
      question: 'What is the overall direction of this passage?',
      correct,
      options: ['Ascending', 'Descending', 'Steady'],
    };
  },

  // Range: what is the note range?
  (fragment) => {
    if (fragment.length < 3) return null;
    const notes = fragment.map(e => e.note);
    const range = Math.max(...notes) - Math.min(...notes);
    const correct = range > 12 ? 'Wide (>octave)' : range > 5 ? 'Medium' : 'Narrow';
    return {
      question: 'What is the pitch range of this passage?',
      correct,
      options: ['Narrow', 'Medium', 'Wide (>octave)'],
    };
  },

  // Tempo: fast or slow notes?
  (fragment) => {
    if (fragment.length < 3) return null;
    const avgDuration = fragment.reduce((s, e) => s + e.duration, 0) / fragment.length;
    const correct = avgDuration < 200 ? 'Fast' : avgDuration < 400 ? 'Moderate' : 'Slow';
    return {
      question: 'What is the tempo of this passage?',
      correct,
      options: ['Fast', 'Moderate', 'Slow'],
    };
  },

  // Dynamics: loud or soft?
  (fragment) => {
    if (fragment.length < 3) return null;
    const avgVelocity = fragment.reduce((s, e) => s + e.velocity, 0) / fragment.length;
    const correct = avgVelocity > 90 ? 'Loud (forte)' : avgVelocity > 50 ? 'Medium (mezzo)' : 'Soft (piano)';
    return {
      question: 'What is the dynamic level of this passage?',
      correct,
      options: ['Soft (piano)', 'Medium (mezzo)', 'Loud (forte)'],
    };
  },
];

export function generateChallenge(song: MusikeySong): MusicChallenge | null {
  if (song.eventCount < 8) return null;

  // Pick a random fragment of 4-8 notes
  const fragLen = 4 + Math.floor(Math.random() * 5);
  const maxStart = Math.max(0, song.eventCount - fragLen);
  const start = Math.floor(Math.random() * (maxStart + 1));
  const end = Math.min(start + fragLen, song.eventCount);
  const fragment = song.events.slice(start, end);

  // Try each question generator in random order
  const shuffled = [...questionGenerators].sort(() => Math.random() - 0.5);
  for (const gen of shuffled) {
    const result = gen(fragment, song);
    if (result) {
      return {
        fragmentStart: start,
        fragmentEnd: end,
        fragment,
        question: result.question,
        correctAnswer: result.correct,
        options: result.options,
      };
    }
  }
  return null;
}

export function verifyChallenge(challenge: MusicChallenge, answer: string): boolean {
  return challenge.correctAnswer === answer;
}
