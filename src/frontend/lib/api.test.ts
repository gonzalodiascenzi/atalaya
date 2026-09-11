// @vitest-environment node
// (jsdom no trae crypto.subtle; Node sí, igual que cualquier navegador en HTTPS)
import { createHash } from 'node:crypto';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { fetchRanks, hashCuerpo, login, logout } from './api';

/** SHA-256 de la cadena vacía: lo que se firma en un POST sin cuerpo. */
const VACIO = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function interceptarFetch() {
  const falso = vi.fn(
    async (_url: string, _init?: RequestInit) =>
      new Response('[]', { status: 200, headers: { 'Content-Type': 'application/json' } }),
  );
  vi.stubGlobal('fetch', falso);
  return falso;
}

function cabecerasDe(falso: ReturnType<typeof interceptarFetch>) {
  return falso.mock.calls[0][1]?.headers as Record<string, string>;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('x-amz-content-sha256 (CloudFront OAC hacia Lambda)', () => {
  it('calcula el SHA-256 en hexadecimal', async () => {
    expect(await hashCuerpo('')).toBe(VACIO);
    expect(await hashCuerpo('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('el hash coincide byte a byte con el cuerpo que viaja, acentos incluidos', async () => {
    // fetch codifica el texto en UTF-8. Si el hash se calculara sobre otra
    // codificación, Lambda rechazaría la firma sólo cuando hay una Ñ.
    const falso = interceptarFetch();
    await login('ÑANDÚ-7', 'frase de prueba');

    const cuerpo = falso.mock.calls[0][1]?.body as string;
    expect(cabecerasDe(falso)['x-amz-content-sha256']).toBe(
      createHash('sha256').update(cuerpo, 'utf8').digest('hex'),
    );
  });

  it('un POST sin cuerpo firma el hash del vacío', async () => {
    const falso = interceptarFetch();
    await logout();
    expect(cabecerasDe(falso)['x-amz-content-sha256']).toBe(VACIO);
  });

  it('un GET no lo manda', async () => {
    const falso = interceptarFetch();
    await fetchRanks();
    expect(cabecerasDe(falso)).not.toHaveProperty('x-amz-content-sha256');
  });
});
