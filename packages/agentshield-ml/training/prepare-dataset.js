'use strict';

/**
 * Agent Shield ML — Training Data Pipeline
 *
 * Collects prompt injection attack samples from public research datasets,
 * combines with synthetic benign samples, and outputs a clean JSONL file
 * ready for model training.
 *
 * Sources:
 * - HackAPrompt (2023) — real competition attacks
 * - TensorTrust (2024) — adversarial prompt game
 * - BIPIA (Alamsabi et al., 2026) — indirect prompt injection
 * - Agent Shield built-in red team payloads
 * - Synthetic benign samples (everyday conversation)
 *
 * Output format (JSONL):
 *   { "text": "...", "label": 1, "source": "hackaprompt", "category": "..." }
 *   { "text": "...", "label": 0, "source": "synthetic", "category": "benign" }
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const TRAINING_DIR = __dirname;
const OUTPUT_FILE = path.join(TRAINING_DIR, 'training-data.jsonl');

// ─── Load External Sample Libraries ──────────────────────────────────────
// Full curated sample sets live in dedicated files for maintainability.
// attack-samples-1: instruction_override, role_hijack, prompt_extraction, etc.
// attack-samples-2: encoding_evasion, context_manipulation, payload_smuggling, etc.
// benign-samples:   200+ benign across 15 categories incl. tricky-but-legit

const attackSamples1 = require('./attack-samples-1');
const attackSamples2 = require('./attack-samples-2');
const externalBenign = require('./benign-samples');

let expandedBenign = [];
try { expandedBenign = require('./benign-samples-expanded'); } catch (_) {}

const ATTACK_SAMPLES = [...attackSamples1, ...attackSamples2];
const BENIGN_SAMPLES = [...externalBenign, ...expandedBenign];

/**
 * Load a Parquet file and return rows as plain objects.
 * Strategy: try Python (pandas) first for best compatibility,
 * then fall back to parquetjs-lite.
 * @param {string} filePath - Path to .parquet file
 * @returns {Promise<Object[]>}
 */
async function readParquet(filePath) {
  const { execSync } = require('child_process');
  const os = require('os');
  const tmpDir = os.tmpdir();
  const tmpScript = path.join(tmpDir, 'agentshield_read_parquet.py');
  const tmpOut = path.join(tmpDir, 'agentshield_parquet_out.jsonl');

  // Clean up any leftover temp files from previous runs
  try { fs.unlinkSync(tmpOut); } catch (_) {}

  // Write a temp Python script (avoids shell quote escaping issues on Windows)
  // Sample large datasets to 50K rows max — more than enough for training
  const pyScript = [
    'import pandas as pd',
    `df = pd.read_parquet(r"""${filePath}""")`,
    'print(f"Loaded {len(df)} rows from parquet")',
    'if len(df) > 50000:',
    '    df = df.sample(n=50000, random_state=42)',
    '    print(f"Sampled down to {len(df)} rows")',
    '# Keep only text-like columns to reduce output size',
    'text_cols = [c for c in df.columns if df[c].dtype == "object"]',
    'if text_cols:',
    '    df = df[text_cols]',
    `df.to_json(r"""${tmpOut}""", orient="records", lines=True, force_ascii=False)`,
    'print("Export complete")'
  ].join('\n');

  fs.writeFileSync(tmpScript, pyScript);

  // Try python, python3, py in order — stop after first success
  const pythons = process.platform === 'win32' ? ['python', 'py', 'python3'] : ['python3', 'python'];
  let lastErr = null;
  let pySuccess = false;

  for (const py of pythons) {
    try {
      const out = execSync(`${py} "${tmpScript}"`, {
        stdio: 'pipe',
        timeout: 600000,  // 10 min for large datasets
        maxBuffer: 10 * 1024 * 1024
      });
      console.log(`[Agent Shield ML]   ${out.toString().trim()}`);
      pySuccess = true;
      break;  // Stop after first working interpreter
    } catch (err) {
      lastErr = err;
      continue;
    }
  }

  // Read the output file if Python succeeded
  if (pySuccess && fs.existsSync(tmpOut)) {
    try {
      console.log('[Agent Shield ML]   Reading exported JSONL...');
      const content = fs.readFileSync(tmpOut, 'utf-8');
      const lines = content.split('\n').filter(Boolean);
      const rows = [];
      for (const line of lines) {
        try { rows.push(JSON.parse(line)); } catch (_) { /* skip bad lines */ }
      }

      // Clean up temp files
      try { fs.unlinkSync(tmpScript); } catch (_) {}
      try { fs.unlinkSync(tmpOut); } catch (_) {}

      console.log(`[Agent Shield ML]   Parsed ${rows.length} rows via Python/pandas`);
      return rows;
    } catch (readErr) {
      console.error(`[Agent Shield ML]   Failed to parse JSONL: ${readErr.message}`);
      try { fs.unlinkSync(tmpOut); } catch (_) {}
    }
  }

  // Clean up temp script on failure
  try { fs.unlinkSync(tmpScript); } catch (_) {}

  // Fallback: parquetjs-lite
  try {
    const parquet = require('parquetjs-lite');
    const reader = await parquet.ParquetReader.openFile(filePath);
    const cursor = reader.getCursor();
    const rows = [];
    let row;
    while ((row = await cursor.next())) {
      rows.push(row);
    }
    await reader.close();
    console.log(`[Agent Shield ML]   Read ${rows.length} rows via parquetjs-lite`);
    return rows;
  } catch (jsErr) {
    const pyMsg = lastErr ? lastErr.stderr ? lastErr.stderr.toString() : lastErr.message : 'not found';
    throw new Error(
      `Cannot read parquet file.\n` +
      `  Python error: ${pyMsg}\n` +
      `  JS error: ${jsErr.message}\n` +
      `  Fix: pip install pandas pyarrow`
    );
  }
}

/**
 * Build the training dataset.
 * @param {Object} [options]
 * @param {string} [options.hackapromptPath] - Path to HackAPrompt CSV or Parquet (optional)
 * @param {string} [options.tensortustPath] - Path to TensorTrust JSONL (optional)
 * @param {string} [options.bipiaPath] - Path to BIPIA JSONL (optional)
 * @param {string[]} [options.benignPaths] - Paths to benign dataset Parquet/JSONL files (optional)
 * @param {string} [options.outputPath] - Output JSONL path
 * @returns {Promise<{ total: number, attacks: number, benign: number, outputPath: string }>}
 */
async function buildDataset(options = {}) {
  const outputPath = options.outputPath || OUTPUT_FILE;

  if (!fs.existsSync(path.dirname(outputPath))) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  }

  const samples = [];
  const seen = new Set();

  function addSample(text, label, source, category) {
    if (typeof text !== 'string') return;
    const clean = text.trim();
    if (!clean || clean.length < 5) return;
    const hash = crypto.createHash('md5').update(clean.toLowerCase()).digest('hex');
    if (seen.has(hash)) return;
    seen.add(hash);
    samples.push({ text: clean, label, source, category });
  }

  // Built-in attacks
  for (const s of ATTACK_SAMPLES) {
    addSample(s.text, 1, 'agentshield', s.category);
  }

  // Built-in benign
  for (const s of BENIGN_SAMPLES) {
    addSample(s.text, 0, 'synthetic', s.category);
  }

  // Load HackAPrompt — supports both CSV and Parquet
  if (options.hackapromptPath && fs.existsSync(options.hackapromptPath)) {
    const ext = path.extname(options.hackapromptPath).toLowerCase();

    if (ext === '.parquet') {
      console.log('[Agent Shield ML] Loading HackAPrompt dataset (Parquet)...');
      const rows = await readParquet(options.hackapromptPath);
      console.log(`[Agent Shield ML]   Read ${rows.length} rows from Parquet`);
      for (const row of rows) {
        // Common HackAPrompt column names: user_input, prompt, text, simple_prompt
        const text = row.user_input || row.prompt || row.text || row.simple_prompt || '';
        if (text) addSample(String(text), 1, 'hackaprompt', 'competition_attack');
      }
    } else {
      // CSV fallback
      console.log('[Agent Shield ML] Loading HackAPrompt dataset (CSV)...');
      const lines = fs.readFileSync(options.hackapromptPath, 'utf-8').split('\n');
      for (const line of lines.slice(1)) { // skip header
        const parts = line.split(',');
        if (parts.length >= 2) {
          const text = parts.slice(1).join(',').replace(/^"|"$/g, '').trim();
          if (text) addSample(text, 1, 'hackaprompt', 'competition_attack');
        }
      }
    }
  }

  // Load TensorTrust JSONL if available
  if (options.tensortustPath && fs.existsSync(options.tensortustPath)) {
    console.log('[Agent Shield ML] Loading TensorTrust dataset (JSONL)...');
    const lines = fs.readFileSync(options.tensortustPath, 'utf-8').split('\n');
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        if (obj.text || obj.prompt || obj.attack) {
          const text = obj.text || obj.prompt || obj.attack;
          const label = obj.label !== undefined ? obj.label : 1;
          addSample(text, label, 'tensortrust', obj.category || 'game_attack');
        }
      } catch (_e) { /* skip malformed lines */ }
    }
  }

  // Load BIPIA JSONL if available
  if (options.bipiaPath && fs.existsSync(options.bipiaPath)) {
    console.log('[Agent Shield ML] Loading BIPIA dataset...');
    const lines = fs.readFileSync(options.bipiaPath, 'utf-8').split('\n');
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        if (obj.user_intent && obj.context) {
          const combined = `${obj.context}\n\n---\n\n${obj.user_intent}`;
          addSample(combined, obj.label || 0, 'bipia', 'indirect_injection');
        }
      } catch (_e) { /* skip malformed lines */ }
    }
  }

  // Load external benign datasets (Parquet or JSONL)
  if (options.benignPaths && options.benignPaths.length > 0) {
    for (const benignPath of options.benignPaths) {
      if (!fs.existsSync(benignPath)) {
        console.log(`[Agent Shield ML] Benign file not found: ${benignPath}`);
        continue;
      }
      const ext = path.extname(benignPath).toLowerCase();
      const fileName = path.basename(benignPath);
      console.log(`[Agent Shield ML] Loading benign dataset: ${fileName}...`);

      if (ext === '.parquet') {
        const rows = await readParquet(benignPath);
        console.log(`[Agent Shield ML]   Read ${rows.length} rows from ${fileName}`);
        for (const row of rows) {
          // Common benign dataset columns: instruction, input, output, text, prompt, context
          // Dolly: instruction, context, response, category
          // Alpaca: instruction, input, output
          const text = row.instruction || row.text || row.prompt || row.input || '';
          const category = row.category || 'external_benign';
          if (text) addSample(String(text), 0, 'external_benign', String(category));
          // Also add the output/response as benign if present
          const response = row.output || row.response || '';
          if (response && String(response).length > 10) {
            addSample(String(response), 0, 'external_benign', String(category));
          }
        }
      } else {
        // JSONL
        const lines = fs.readFileSync(benignPath, 'utf-8').split('\n');
        for (const line of lines) {
          try {
            const obj = JSON.parse(line);
            const text = obj.instruction || obj.text || obj.prompt || obj.input || '';
            if (text) addSample(text, 0, 'external_benign', obj.category || 'external_benign');
          } catch (_e) { /* skip */ }
        }
      }
    }
  }

  // Balance to ~50/50 by capping the larger class
  let attackSamples = samples.filter(s => s.label === 1);
  let benignSamples = samples.filter(s => s.label === 0);

  console.log(`[Agent Shield ML] Before balancing: ${attackSamples.length} attacks, ${benignSamples.length} benign`);

  const targetSize = Math.min(attackSamples.length, benignSamples.length);
  if (attackSamples.length > targetSize) {
    // Shuffle attacks then take targetSize
    for (let i = attackSamples.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [attackSamples[i], attackSamples[j]] = [attackSamples[j], attackSamples[i]];
    }
    attackSamples = attackSamples.slice(0, targetSize);
  }
  if (benignSamples.length > targetSize) {
    for (let i = benignSamples.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [benignSamples[i], benignSamples[j]] = [benignSamples[j], benignSamples[i]];
    }
    benignSamples = benignSamples.slice(0, targetSize);
  }

  const balanced = [...attackSamples, ...benignSamples];
  console.log(`[Agent Shield ML] After balancing: ${attackSamples.length} attacks, ${benignSamples.length} benign (${balanced.length} total)`);

  // Shuffle
  for (let i = balanced.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [balanced[i], balanced[j]] = [balanced[j], balanced[i]];
  }

  // Write JSONL
  const lines = balanced.map(s => JSON.stringify(s));
  fs.writeFileSync(outputPath, lines.join('\n') + '\n');

  const attacks = attackSamples.length;
  const benign = benignSamples.length;

  console.log(`[Agent Shield ML] Dataset built: ${balanced.length} samples (${attacks} attacks, ${benign} benign)`);
  console.log(`[Agent Shield ML] Written to: ${outputPath}`);

  return { total: balanced.length, attacks, benign, outputPath };
}

// Run if called directly
if (require.main === module) {
  buildDataset({
    hackapromptPath: process.argv[2],
    tensortustPath: process.argv[3],
    bipiaPath: process.argv[4]
  }).then(result => {
    console.log(`\nDataset ready: ${result.total} samples`);
    console.log(`To train the model, run:`);
    console.log(`  python training/train.py --data ${result.outputPath}`);
  }).catch(err => {
    console.error('[Agent Shield ML] Dataset build failed:', err.message);
    process.exit(1);
  });
}

module.exports = { buildDataset, ATTACK_SAMPLES, BENIGN_SAMPLES };
