'use strict';

/**
 * Agent Shield ML — External Dataset Loader
 *
 * Drop your downloaded dataset files into datasets/raw/ and run this script.
 * It auto-detects HackAPrompt (.parquet or .csv) and TensorTrust (.jsonl).
 *
 * Usage:
 *   node packages/agentshield-ml/training/load-external-datasets.js
 *
 * Or specify paths directly:
 *   node packages/agentshield-ml/training/load-external-datasets.js \
 *     --hackaprompt path/to/hackaprompt.parquet \
 *     --tensortrust path/to/dataset_for_huggingface.jsonl
 */

const fs = require('fs');
const path = require('path');
const { buildDataset } = require('./prepare-dataset');

const RAW_DIR = path.join(__dirname, '..', '..', '..', 'datasets', 'raw');

function findFile(dir, pattern) {
  if (!fs.existsSync(dir)) return null;
  const files = fs.readdirSync(dir);
  return files.find(f => pattern.test(f)) || null;
}

function parseArgs(args) {
  const opts = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--hackaprompt' && args[i + 1]) opts.hackapromptPath = args[++i];
    if (args[i] === '--tensortrust' && args[i + 1]) opts.tensortustPath = args[++i];
    if (args[i] === '--bipia' && args[i + 1]) opts.bipiaPath = args[++i];
    if (args[i] === '--output' && args[i + 1]) opts.outputPath = args[++i];
  }
  return opts;
}

async function main() {
  const cliOpts = parseArgs(process.argv.slice(2));

  // Auto-detect files in datasets/raw/ if not specified via CLI
  if (!cliOpts.hackapromptPath) {
    const match = findFile(RAW_DIR, /hackaprompt\.(parquet|csv)$/i);
    if (match) cliOpts.hackapromptPath = path.join(RAW_DIR, match);
  }
  if (!cliOpts.tensortustPath) {
    const match = findFile(RAW_DIR, /dataset_for_huggingface\.jsonl$/i)
      || findFile(RAW_DIR, /tensortrust.*\.jsonl$/i);
    if (match) cliOpts.tensortustPath = path.join(RAW_DIR, match);
  }

  console.log('[Agent Shield ML] External Dataset Loader');
  console.log('─'.repeat(50));
  console.log(`  HackAPrompt: ${cliOpts.hackapromptPath || '(not found)'}`);
  console.log(`  TensorTrust: ${cliOpts.tensortustPath || '(not found)'}`);
  console.log(`  BIPIA:       ${cliOpts.bipiaPath || '(not found)'}`);
  console.log('─'.repeat(50));

  if (!cliOpts.hackapromptPath && !cliOpts.tensortustPath && !cliOpts.bipiaPath) {
    console.log('\nNo external datasets found.');
    console.log(`\nTo use this script, either:`);
    console.log(`  1. Copy your files to: ${RAW_DIR}/`);
    console.log(`     - hackaprompt.parquet (or .csv)`);
    console.log(`     - dataset_for_huggingface.jsonl`);
    console.log(`  2. Or specify paths directly:`);
    console.log(`     node ${path.relative(process.cwd(), __filename)} \\`);
    console.log(`       --hackaprompt /path/to/hackaprompt.parquet \\`);
    console.log(`       --tensortrust /path/to/dataset_for_huggingface.jsonl`);
    process.exit(0);
  }

  const result = await buildDataset(cliOpts);

  console.log(`\nDone! ${result.total} samples written to:`);
  console.log(`  ${result.outputPath}`);
  console.log(`\nNext step — train the model:`);
  console.log(`  python packages/agentshield-ml/training/train.py --data ${result.outputPath}`);
}

main().catch(err => {
  console.error('[Agent Shield ML] Error:', err.message || err);
  console.error('[Agent Shield ML] Stack:', err.stack || '(no stack)');
  process.exit(1);
});
