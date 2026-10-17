import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
for (const stage of ['stage2', 'stage3', 'stage4', 'stage5_x', 'registry']) {
  test(`Influence ${stage} publishes a queued run without stale-base conflicts or unstaged files`, async () => {
    const workflowPath = stage === 'registry' ? '.github/workflows/validate_influence_registry.yml'
      : `.github/workflows/build_influence_${stage}.yml`;
    const workflow = await fs.readFile(path.join(root, workflowPath), 'utf8');
    const section = workflow.match(/      - name: Commit[^\n]*\n        shell: bash\n        run: \|\n((?:          [^\n]*\n|\n)+)/)?.[1];
    assert(section, 'Commit step must be available for the publishing integration test');
    const script = section.split('\n').map(line => line.startsWith('          ') ? line.slice(10) : line).join('\n');
    const add = script.match(/git add \\\n([\s\S]*?)\n\n/)?.[1];
    assert(add);
    const stagedPaths = add.split('\n').map(line => line.trim().replace(/\\$/, '').trim()).filter(Boolean);
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'mard-publish-'));
    const working = path.join(temp, 'work');
    const remote = path.join(temp, 'origin.git');
    const run = (command, args, options = {}) => execFileSync(command, args, { cwd: working, stdio: 'pipe', ...options });
    try {
      await fs.mkdir(working);
      run('git', ['init', '--initial-branch=main']);
      run('git', ['init', '--bare', remote]);
      run('git', ['config', 'user.name', 'Fixture']);
      run('git', ['config', 'user.email', 'fixture@example.test']);
      const allPaths = [...new Set([...stagedPaths, 'data/influence/validation_report.json',
        ...(stage === 'stage5_x' ? ['public/influence_nitter_preflight.json'] : [])])];
      for (const file of allPaths) {
        await fs.mkdir(path.dirname(path.join(working, file)), { recursive: true });
        await fs.writeFile(path.join(working, file), '{}\n');
      }
      run('git', ['add', '.']); run('git', ['commit', '-m', 'Baseline']);
      run('git', ['remote', 'add', 'origin', remote]); run('git', ['push', '-u', 'origin', 'main']);
      const triggerSha = run('git', ['rev-parse', 'HEAD']).toString().trim();
      // Another writer finishes while this job is waiting in the concurrency group.
      // A checkout of the old trigger SHA recreates the real validation-report conflict.
      const upstream = path.join(temp, 'previous-job');
      run('git', ['clone', '--branch', 'main', remote, upstream]);
      const previous = (args) => run('git', args, { cwd: upstream });
      previous(['config', 'user.name', 'Previous job']);
      previous(['config', 'user.email', 'previous@example.test']);
      await fs.writeFile(path.join(upstream, 'data/influence/validation_report.json'), '{"generated_by":"previous-job"}\n');
      previous(['add', '.']); previous(['commit', '-m', 'Previous collection finished']); previous(['push']);
      run('git', ['fetch', 'origin', 'main']);
      const checkout = workflow.match(/      - name: Checkout repository\n[\s\S]*?(?=\n      - name:)/)?.[0];
      const configuredRef = checkout?.match(/\n\s+ref:\s*([^\n]+)/)?.[1]?.trim();
      const target = ['${{ github.ref_name }}', 'main', 'refs/heads/main'].includes(configuredRef)
        ? 'origin/main' : configuredRef || triggerSha;
      run('git', ['checkout', '-B', 'main', target]);
      // The real validator writes a tracked report in every collection workflow.
      // Omitting that file reproduces the actual unstaged-change rebase failure.
      run(process.execPath, [path.join(root, 'scripts/influence/validate_influence_registry.mjs')], {
        env: { ...process.env, MARD_INFLUENCE_REGISTRY: path.join(root, 'config/influence/mard_influence_registry_v1.json') }
      });
      for (const file of stagedPaths.filter(file => file !== 'data/influence/validation_report.json')) {
        await fs.writeFile(path.join(working, file), '{"updated":true}\n');
      }
      if (stage === 'stage5_x') await fs.writeFile(path.join(working, 'public/influence_nitter_preflight.json'), '{"updated":true}\n');
      run('bash', ['-e', '-c', script], { env: { ...process.env, GITHUB_REF_NAME: 'main' } });
      assert.equal(run('git', ['status', '--porcelain']).toString(), '');
      assert.equal(run('git', ['rev-parse', 'HEAD']).toString(), run('git', ['rev-parse', 'origin/main']).toString());
    } finally { await fs.rm(temp, { recursive: true, force: true }); }
  });
}
