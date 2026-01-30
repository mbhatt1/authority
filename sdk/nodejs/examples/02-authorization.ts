/**
 * Example 2: Authorization & Policy Enforcement
 *
 * Demonstrates authorization checks and policy decision making
 */

import {
  AuthorityKernel,
  OperationDeniedError,
  InvalidArgumentError,
} from '../src/index';

async function main() {
  console.log('=== Example 2: Authorization & Policy Enforcement ===\n');

  const ak = new AuthorityKernel({ debug: false });

  try {
    await ak.init();
    console.log('✅ Kernel initialized\n');

    // ====================================================================
    // Example 1: Simple authorization check (boolean)
    // ====================================================================
    console.log('1️⃣  Checking if read operation is allowed on /tmp/test.txt...');
    const readAllowed = await ak.authorize('read', '/tmp/test.txt');

    if (readAllowed) {
      console.log('✅ Read operation is ALLOWED');
      console.log('   You can proceed with reading the file\n');
    } else {
      console.log('❌ Read operation is DENIED');
      console.log('   You do not have permission to read this file\n');
    }

    // ====================================================================
    // Example 2: Get detailed authorization info
    // ====================================================================
    console.log('2️⃣  Getting detailed authorization information...');
    const writeDetails = await ak.authorizeDetails('write', '/tmp/output.txt');

    console.log('✅ Authorization details retrieved:');
    console.log(`   Operation: ${writeDetails.operation}`);
    console.log(`   Target: ${writeDetails.target}`);
    console.log(`   Authorized: ${writeDetails.authorized}`);
    if (writeDetails.ttlMs) {
      console.log(`   TTL: ${writeDetails.ttlMs}ms`);
    }
    if (writeDetails.reason) {
      console.log(`   Reason: ${writeDetails.reason}`);
    }
    console.log();

    // ====================================================================
    // Example 3: Tool execution authorization
    // ====================================================================
    console.log('3️⃣  Checking tool execution authorization...');
    const toolOps = [
      { tool: 'http_get', url: 'https://api.example.com' },
      { tool: 'file_write', path: '/sensitive/data.txt' },
      { tool: 'bash', cmd: 'rm -rf /' },
    ];

    for (const op of toolOps) {
      const key = 'tool' in op ? `${op.tool}` : 'unknown';
      console.log(`   Checking: ${key}...`);

      try {
        const allowed = await ak.authorize('execute', key);
        if (allowed) {
          console.log(`   ✅ Allowed`);
        } else {
          console.log(`   ⛔ Denied by policy`);
        }
      } catch (err) {
        if (err instanceof OperationDeniedError) {
          console.log(`   ⛔ Denied: ${err.message}`);
        } else {
          throw err;
        }
      }
    }
    console.log();

    // ====================================================================
    // Example 4: File access authorization check
    // ====================================================================
    console.log('4️⃣  Checking various file access patterns...');
    const filePaths = [
      { path: '/etc/passwd', op: 'read' },
      { path: '/etc/shadow', op: 'read' },
      { path: '/tmp/scratch', op: 'write' },
      { path: '/home/user/.ssh/id_rsa', op: 'read' },
    ];

    for (const file of filePaths) {
      console.log(`   ${file.op.toUpperCase()} ${file.path}...`);

      try {
        const allowed = await ak.authorize(file.op, file.path);
        if (allowed) {
          console.log(`   ✅ Allowed`);
        } else {
          console.log(`   ⛔ Denied by policy`);
        }
      } catch (err) {
        if (err instanceof OperationDeniedError) {
          console.log(`   ⛔ Denied: ${err.message}`);
        } else {
          throw err;
        }
      }
    }
    console.log();

    // ====================================================================
    // Example 5: Network authorization
    // ====================================================================
    console.log('5️⃣  Checking network access authorization...');
    const networkOps = [
      { target: 'api.openai.com:443', op: 'connect' },
      { target: 'api.anthropic.com:443', op: 'connect' },
      { target: 'attacker.com:443', op: 'connect' },
      { target: 'localhost:8080', op: 'connect' },
    ];

    for (const net of networkOps) {
      console.log(`   ${net.op.toUpperCase()} ${net.target}...`);

      try {
        const allowed = await ak.authorize(net.op, net.target);
        if (allowed) {
          console.log(`   ✅ Allowed`);
        } else {
          console.log(`   ⛔ Denied by policy`);
        }
      } catch (err) {
        if (err instanceof OperationDeniedError) {
          console.log(`   ⛔ Denied: ${err.message}`);
        } else {
          throw err;
        }
      }
    }
    console.log();

    // ====================================================================
    // Example 6: LLM authorization
    // ====================================================================
    console.log('6️⃣  Checking LLM access authorization...');
    const llmModels = ['gpt-4', 'claude-3-sonnet', 'custom-internal-model'];

    for (const model of llmModels) {
      console.log(`   LLM inference with ${model}...`);

      try {
        const allowed = await ak.authorize('inference', model);
        if (allowed) {
          console.log(`   ✅ Allowed`);
        } else {
          console.log(`   ⛔ Denied by policy`);
        }
      } catch (err) {
        if (err instanceof OperationDeniedError) {
          console.log(`   ⛔ Denied: ${err.message}`);
        } else {
          throw err;
        }
      }
    }
    console.log();

    // ====================================================================
    // Example 7: Get last denial information
    // ====================================================================
    console.log('7️⃣  Checking last denial information...');
    const lastDenial = await ak.getLastDenial();

    if (lastDenial) {
      console.log('✅ Last denial info:');
      console.log(`   Reason: ${lastDenial.reason}`);
      if (lastDenial.capabilityRequired) {
        console.log(`   Capability Required: ${lastDenial.capabilityRequired}`);
      }
      if (lastDenial.suggestion) {
        console.log(`   Suggestion: ${lastDenial.suggestion}`);
      }
    } else {
      console.log('✅ No previous denials\n');
    }

    // ====================================================================
    // Summary
    // ====================================================================
    console.log('\n=== Summary ===');
    console.log('✅ Successfully demonstrated:');
    console.log('   • Simple authorization checks (boolean)');
    console.log('   • Detailed authorization information');
    console.log('   • Tool execution authorization');
    console.log('   • File access patterns');
    console.log('   • Network access control');
    console.log('   • LLM model authorization');
    console.log('   • Denial tracking');
  } catch (err) {
    if (err instanceof Error) {
      console.error('❌ Error:', err.message);
      if ('code' in err) {
        console.error('   Code:', (err as any).code);
      }
    }
    process.exit(1);
  } finally {
    console.log('\nShutting down kernel...');
    await ak.shutdown();
    console.log('✅ Kernel shutdown complete');
  }
}

// Run the example
main().catch(console.error);
