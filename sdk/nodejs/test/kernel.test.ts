/**
 * Unit tests for AuthorityKernel
 */

import { AuthorityKernel } from '../src/kernel';
import { AuthorityKernelError, OperationDeniedError } from '../src/errors';

describe('AuthorityKernel', () => {
  describe('Initialization', () => {
    test('should create instance with default options', () => {
      const ak = new AuthorityKernel();
      expect(ak).toBeDefined();
    });

    test('should create instance with custom options', () => {
      const ak = new AuthorityKernel({
        debug: true,
        syscallTimeout: 5000,
        maxObjectSize: 5 * 1024 * 1024,
      });
      expect(ak).toBeDefined();
    });

    test('should handle missing libak gracefully', () => {
      expect(() => {
        new AuthorityKernel({ libakPath: '/nonexistent/libak.so' });
      }).toThrow(AuthorityKernelError);
    });
  });

  describe('Error Handling', () => {
    test('should create proper error instances', () => {
      expect(new AuthorityKernelError(-1, 'test')).toBeInstanceOf(Error);
      expect(new OperationDeniedError(-1, 'test')).toBeInstanceOf(AuthorityKernelError);
    });

    test('should format error messages correctly', () => {
      const err = new AuthorityKernelError(-5, 'Budget exceeded', 'tokens');
      expect(err.message).toContain('[-5]');
      expect(err.message).toContain('Budget exceeded');
      expect(err.message).toContain('tokens');
    });
  });

  describe('SDK Info', () => {
    test('should export SDK version', () => {
      const { getSdkInfo } = require('../src/index');
      const info = getSdkInfo();
      expect(info).toHaveProperty('version');
      expect(info).toHaveProperty('name');
      expect(info.name).toBe('@authority/nanos');
    });
  });

  describe('Type Exports', () => {
    test('should export error classes', () => {
      const {
        AuthorityKernelError,
        OperationDeniedError,
        CapabilityError,
        BudgetExceededError,
      } = require('../src/index');

      expect(AuthorityKernelError).toBeDefined();
      expect(OperationDeniedError).toBeDefined();
      expect(CapabilityError).toBeDefined();
      expect(BudgetExceededError).toBeDefined();
    });

    test('should export type enums', () => {
      const { Syscall, ErrorCode, CapabilityType } = require('../src/index');

      expect(Syscall).toBeDefined();
      expect(Syscall.READ).toBe(1024);
      expect(Syscall.ALLOC).toBe(1025);

      expect(ErrorCode).toBeDefined();
      expect(ErrorCode.OK).toBe(0);
      expect(ErrorCode.DENIED).toBe(-1);

      expect(CapabilityType).toBeDefined();
    });
  });

  describe('Async Dispose', () => {
    test('should support Symbol.asyncDispose', async () => {
      const ak = new AuthorityKernel();
      expect(ak[Symbol.asyncDispose]).toBeDefined();
    });
  });
});
