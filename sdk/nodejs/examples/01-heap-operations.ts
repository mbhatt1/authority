/**
 * Example 1: Typed Heap Operations
 *
 * Demonstrates basic heap operations: allocate, read, update, delete
 */

import { AuthorityKernel } from '../src/index';

async function main() {
  console.log('=== Example 1: Typed Heap Operations ===\n');

  // Create and initialize kernel
  console.log('📦 Initializing Authority Kernel...');
  const ak = new AuthorityKernel({ debug: false });

  try {
    await ak.init();
    console.log('✅ Kernel initialized\n');

    // ====================================================================
    // Example 1: Allocate an object
    // ====================================================================
    console.log('1️⃣  Allocating counter object...');
    const counterData = { value: 0, name: 'counter', created: new Date().toISOString() };
    const counterHandle = await ak.alloc('counter', counterData);

    console.log(`✅ Allocated counter`);
    console.log(`   Handle ID: ${counterHandle.id}`);
    console.log(`   Version: ${counterHandle.version}\n`);

    // ====================================================================
    // Example 2: Read the object
    // ====================================================================
    console.log('2️⃣  Reading counter object...');
    const readBuffer = await ak.read(counterHandle);
    const readData = JSON.parse(new TextDecoder().decode(readBuffer));

    console.log('✅ Read counter');
    console.log(`   Data: ${JSON.stringify(readData)}\n`);

    // ====================================================================
    // Example 3: Update the object with JSON Patch
    // ====================================================================
    console.log('3️⃣  Updating counter (incrementing value)...');
    const newVersion = await ak.write(counterHandle, [
      { op: 'replace', path: '/value', value: readData.value + 1 },
      { op: 'replace', path: '/updated', value: new Date().toISOString() },
    ]);

    console.log(`✅ Updated counter`);
    console.log(`   New version: ${newVersion}\n`);

    // Verify update
    const updatedBuffer = await ak.read(counterHandle);
    const updatedData = JSON.parse(new TextDecoder().decode(updatedBuffer));
    console.log(`   Data: ${JSON.stringify(updatedData)}\n`);

    // ====================================================================
    // Example 4: Complex object with arrays
    // ====================================================================
    console.log('4️⃣  Creating conversation object with messages...');
    const conversationData = {
      id: 'conv-001',
      messages: [
        { role: 'system', content: 'You are helpful' },
        { role: 'user', content: 'Hello!' },
      ],
      metadata: { model: 'gpt-4', temperature: 0.7 },
    };

    const conversationHandle = await ak.alloc('conversation', conversationData);
    console.log('✅ Allocated conversation\n');

    // Add a new message using JSON Patch
    console.log('5️⃣  Adding assistant response...');
    await ak.write(conversationHandle, [
      {
        op: 'add',
        path: '/messages/-',
        value: { role: 'assistant', content: 'Hi there! How can I help?' },
      },
    ]);

    console.log('✅ Added message to conversation\n');

    // Read updated conversation
    const convBuffer = await ak.read(conversationHandle);
    const convData = JSON.parse(new TextDecoder().decode(convBuffer));
    console.log(`   Message count: ${convData.messages.length}`);
    console.log(`   Last message: "${convData.messages[convData.messages.length - 1].content}"\n`);

    // ====================================================================
    // Example 5: Delete object
    // ====================================================================
    console.log('6️⃣  Deleting counter object...');
    await ak.delete(counterHandle);
    console.log('✅ Deleted counter\n');

    // Try to read deleted object (should fail)
    console.log('7️⃣  Attempting to read deleted object (expected to fail)...');
    try {
      await ak.read(counterHandle);
      console.log('❌ Expected error but operation succeeded');
    } catch (err) {
      if (err instanceof Error) {
        console.log(`✅ Got expected error: ${err.name}\n`);
      }
    }

    // ====================================================================
    // Summary
    // ====================================================================
    console.log('=== Summary ===');
    console.log('✅ Successfully demonstrated:');
    console.log('   • Allocating typed objects');
    console.log('   • Reading objects with versioning');
    console.log('   • Updating objects with JSON Patch');
    console.log('   • Working with complex data structures');
    console.log('   • Deleting objects');
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
