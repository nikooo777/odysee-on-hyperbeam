import { describe, it, expect } from 'vitest';
import { classifyTarget, isTxidTarget } from '../src/hb.js';
import { ONCHAIN_TXID, ONCHAIN_CLAIM_ID } from './fixtures.js';

describe('classifyTarget', () => {
  it('classifies a 64-hex transaction id', () => {
    const target = classifyTarget(ONCHAIN_TXID);
    expect(target.kind).toBe('txid');
    expect(target.value).toBe(ONCHAIN_TXID);
    expect(isTxidTarget(target)).toBe(true);
  });

  it('lowercases transaction ids', () => {
    const target = classifyTarget(ONCHAIN_TXID.toUpperCase());
    expect(target.kind).toBe('txid');
    expect(target.value).toBe(ONCHAIN_TXID);
  });

  it('classifies an explicit txid:nout outpoint', () => {
    const target = classifyTarget(`${ONCHAIN_TXID}:3`);
    expect(target.kind).toBe('outpoint');
    expect(target.value).toBe(ONCHAIN_TXID);
    expect(target.nout).toBe(3);
    expect(isTxidTarget(target)).toBe(true);
  });

  it('keeps 40-hex inputs as claim ids', () => {
    const target = classifyTarget(ONCHAIN_CLAIM_ID);
    expect(target.kind).toBe('claim-id');
    expect(target.value).toBe(ONCHAIN_CLAIM_ID);
    expect(isTxidTarget(target)).toBe(false);
  });

  it('keeps URL inputs as urls', () => {
    expect(classifyTarget('lbry://@channel/video').kind).toBe('url');
    expect(classifyTarget('https://odysee.com/@c/v').kind).toBe('url');
  });

  it('falls back to name for everything else', () => {
    expect(classifyTarget('some-claim-name').kind).toBe('name');
    expect(classifyTarget(ONCHAIN_TXID.slice(0, 63)).kind).toBe('name');
    expect(classifyTarget(`${ONCHAIN_TXID}:`).kind).toBe('name');
    expect(classifyTarget(`${ONCHAIN_TXID}:x`).kind).toBe('name');
  });
});
