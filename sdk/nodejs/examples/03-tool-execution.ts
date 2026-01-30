/**
 * Example 3: WASM Tool Execution & Sandboxing
 *
 * Demonstrates tool execution with sandboxing, capability gates, and resource limits
 */

import {
  AuthorityKernel,
  OperationDeniedError,
  InvalidArgumentError,
} from '../src/index';

async function main() {
  console.log('=== Example 3: WASM Tool Execution & Sandboxing ===\n');

  const ak = new AuthorityKernel({ debug: false });

  try {
    await ak.init();
    console.log('✅ Kernel initialized\n');

    // ====================================================================
    // Example 1: Execute a simple calculation tool
    // ====================================================================
    console.log('1️⃣  Executing calculation tool...');
    try {
      // Tool execution with arguments
      const calcResult = await ak.toolCall('calculator', {
        operation: 'add',
        operands: [42, 8],
      });

      const resultData = JSON.parse(new TextDecoder().decode(calcResult));
      console.log('✅ Calculator tool executed');
      console.log(`   Operation: add(42, 8)`);
      console.log(`   Result: ${resultData.result}\n`);
    } catch (err) {
      if (err instanceof OperationDeniedError) {
        console.log('⛔ Calculator tool denied by policy');
        console.log(`   Message: ${err.message}\n`);
      } else if (err instanceof InvalidArgumentError) {
        console.log('⛔ Invalid arguments to calculator');
        console.log(`   Message: ${err.message}\n`);
      } else {
        throw err;
      }
    }

    // ====================================================================
    // Example 2: Execute string processing tool
    // ====================================================================
    console.log('2️⃣  Executing string processing tool...');
    try {
      const strResult = await ak.toolCall('string_utils', {
        operation: 'uppercase',
        input: 'hello world',
      });

      const resultData = JSON.parse(new TextDecoder().decode(strResult));
      console.log('✅ String tool executed');
      console.log(`   Input: "hello world"`);
      console.log(`   Operation: uppercase`);
      console.log(`   Result: "${resultData.result}"\n`);
    } catch (err) {
      if (err instanceof OperationDeniedError) {
        console.log('⛔ String tool denied by policy\n');
      } else {
        throw err;
      }
    }

    // ====================================================================
    // Example 3: Execute crypto tool (likely restricted)
    // ====================================================================
    console.log('3️⃣  Executing cryptography tool (may be restricted)...');
    try {
      const cryptoResult = await ak.toolCall('crypto', {
        operation: 'hash',
        algorithm: 'sha256',
        input: 'sensitive data',
      });

      const resultData = JSON.parse(new TextDecoder().decode(cryptoResult));
      console.log('✅ Crypto tool executed');
      console.log(`   Algorithm: sha256`);
      console.log(`   Result: ${resultData.hash}\n`);
    } catch (err) {
      if (err instanceof OperationDeniedError) {
        console.log('⛔ Crypto tool denied by policy');
        console.log('   (Typical for untrusted applications)\n');
      } else {
        throw err;
      }
    }

    // ====================================================================
    // Example 4: Execute JSON manipulation tool
    // ====================================================================
    console.log('4️⃣  Executing JSON manipulation tool...');
    try {
      const jsonData = {
        name: 'Alice',
        email: 'alice@example.com',
        roles: ['admin', 'developer'],
      };

      const jsonResult = await ak.toolCall('json_utils', {
        operation: 'prettify',
        data: JSON.stringify(jsonData),
      });

      const resultData = JSON.parse(new TextDecoder().decode(jsonResult));
      console.log('✅ JSON tool executed');
      console.log('   Input: {"name":"Alice","email":"alice@example.com",...}');
      console.log(`   Operation: prettify`);
      console.log(`   Output:\n${resultData.formatted}\n`);
    } catch (err) {
      if (err instanceof OperationDeniedError) {
        console.log('⛔ JSON tool denied by policy\n');
      } else {
        throw err;
      }
    }

    // ====================================================================
    // Example 5: Check tool capabilities before execution
    // ====================================================================
    console.log('5️⃣  Checking tool capabilities...');
    const toolsToCheck = [
      'calculator',
      'string_utils',
      'crypto',
      'file_processor',
      'http_client',
    ];

    for (const tool of toolsToCheck) {
      try {
        const allowed = await ak.authorize('execute', tool);
        if (allowed) {
          console.log(`   ✅ ${tool} - ALLOWED`);
        } else {
          console.log(`   ⛔ ${tool} - DENIED`);
        }
      } catch (err) {
        if (err instanceof OperationDeniedError) {
          console.log(`   ⛔ ${tool} - DENIED (error: ${err.message})`);
        } else {
          throw err;
        }
      }
    }
    console.log();

    // ====================================================================
    // Example 6: Tool execution with large arguments
    // ====================================================================
    console.log('6️⃣  Executing tool with large arguments...');
    try {
      // Simulate processing a large document
      const largeText = 'Lorem ipsum dolor sit amet, '.repeat(1000);

      const textResult = await ak.toolCall('text_analyzer', {
        operation: 'analyze',
        text: largeText,
      });

      const resultData = JSON.parse(new TextDecoder().decode(textResult));
      console.log('✅ Text analyzer executed');
      console.log(`   Input size: ${largeText.length} bytes`);
      console.log(`   Word count: ${resultData.wordCount}`);
      console.log(`   Unique words: ${resultData.uniqueWords}\n`);
    } catch (err) {
      if (err instanceof OperationDeniedError) {
        console.log('⛔ Text analyzer denied by policy\n');
      } else {
        throw err;
      }
    }

    // ====================================================================
    // Example 7: Check budget impact of tool execution
    // ====================================================================
    console.log('7️⃣  Checking budget status after tool executions...');
    const budgetStatus = await ak.getBudgetStatus();

    console.log('✅ Budget status:');
    console.log(`   Tokens used: ${budgetStatus.tokens.used} / ${budgetStatus.tokens.limit}`);
    console.log(`   Remaining: ${budgetStatus.tokens.remaining}`);
    if (budgetStatus.wallTime) {
      console.log(
        `   Wall time: ${budgetStatus.wallTime.used}ms / ${budgetStatus.wallTime.limit}ms`
      );
    }
    if (budgetStatus.toolCalls) {
      console.log(
        `   Tool calls: ${budgetStatus.toolCalls.used} / ${budgetStatus.toolCalls.limit}`
      );
    }
    console.log();

    // ====================================================================
    // Example 8: Tool execution with timeout handling
    // ====================================================================
    console.log('8️⃣  Executing long-running tool...');
    try {
      const longResult = await ak.toolCall('ml_model', {
        operation: 'classify',
        text: 'This is a test document for classification',
      });

      const resultData = JSON.parse(new TextDecoder().decode(longResult));
      console.log('✅ ML model executed');
      console.log(`   Classification: ${resultData.classification}`);
      console.log(`   Confidence: ${resultData.confidence}\n`);
    } catch (err) {
      if (err instanceof OperationDeniedError) {
        console.log('⛔ ML model denied by policy');
        console.log('   (Common for resource-intensive tools)\n');
      } else {
        throw err;
      }
    }

    // ====================================================================
    // Summary
    // ====================================================================
    console.log('=== Summary ===');
    console.log('✅ Successfully demonstrated:');
    console.log('   • WASM tool execution');
    console.log('   • Tool argument passing');
    console.log('   • Capability-based access control');
    console.log('   • Tool authorization checks');
    console.log('   • Budget tracking for tool calls');
    console.log('   • Error handling for denied operations');
    console.log('   • Result parsing and processing');
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
