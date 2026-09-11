/**
 * El panel de veredicto es el producto. Si esto se rompe, ATALAYA vuelve a
 * ser un clicker: por eso cada regla visible tiene su test.
 */
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mission } from '@/lib/types';

vi.mock('@/lib/api', async () => {
  const real = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...real, submitVerdict: vi.fn() };
});

import { ApiRejection, submitVerdict } from '@/lib/api';
import VerdictPanel from './VerdictPanel';

function mision(extra: Partial<Mission> = {}): Mission {
  return {
    mission_id: 'MSN-TEST0001',
    title: 'Misión de prueba',
    briefing: 'Briefing.',
    severity: 'high',
    difficulty: 3,
    xp_reward: 100,
    required_rank: 'NOVATO',
    source: 'CISA KEV',
    tlp: 'TLP:CLEAR',
    attack_technique: 'T1190',
    attack_tactic: 'initial-access',
    malware_family: 'Sin atribución',
    ioc_defanged: 'CVE-2026-0001',
    ioc_pattern: "[vulnerability:name = 'CVE-2026-0001']",
    objectives: ['Revisar'],
    detected_at: new Date().toISOString(),
    expires_in_minutes: 240,
    status: 'OPEN',
    object_refs: [],
    locked: false,
    independent_sources: 1,
    awaiting_corroboration: false,
    my_verdict: null,
    ...extra,
  };
}

function montar(m = mision(), canOperate = true) {
  const onSubmitted = vi.fn();
  const onSessionExpired = vi.fn();
  render(
    <VerdictPanel
      mission={m}
      canOperate={canOperate}
      onSubmitted={onSubmitted}
      onSessionExpired={onSessionExpired}
    />,
  );
  return { onSubmitted, onSessionExpired, user: userEvent.setup() };
}

const botonSellar = () => screen.getByRole('button', { name: /sellar veredicto/i });

describe('VerdictPanel', () => {
  // Con llaves A PROPÓSITO. `() => mock.mockReset()` devuelve el propio mock,
  // y si un beforeEach devuelve una función Vitest la ejecuta como teardown:
  // llamaba a submitVerdict() después de cada test. Con un mock que rechaza,
  // ese teardown fallaba y el test se marcaba rojo aunque el componente
  // hubiera atrapado el error y mostrado el alerta correctamente.
  beforeEach(() => {
    vi.mocked(submitVerdict).mockReset();
  });

  it('no deja sellar sin elegir una llamada', () => {
    montar();
    expect(botonSellar()).toBeDisabled();
  });

  it('muestra cuánto se gana y cuánto se pierde', async () => {
    const { user } = montar();
    await user.click(screen.getByRole('radio', { name: 'malicioso' }));
    const vista = screen.getByTestId('vista-previa-pago');
    // 70% sobre base 100: +64 si acierta, −96 si se equivoca (tabla de Python).
    expect(vista).toHaveTextContent('+64');
    expect(vista).toHaveTextContent('-96');
  });

  it('al 50% explica que cubrirse no paga', async () => {
    const { user } = montar();
    await user.click(screen.getByRole('radio', { name: 'malicioso' }));
    const slider = screen.getByRole('slider');
    // jsdom no implementa el teclado sobre <input type="range">: las flechas
    // no mueven nada. Se fija el valor directamente, como lo haría el drag.
    fireEvent.change(slider, { target: { value: '50' } });
    expect(slider).toHaveValue('50');
    expect(screen.getByTestId('vista-previa-pago')).toHaveTextContent(/moneda al aire/i);
  });

  it('exige fundamento desde el 80%', async () => {
    const { user } = montar();
    await user.click(screen.getByRole('radio', { name: 'benigno' }));
    const slider = screen.getByRole('slider');
    fireEvent.change(slider, { target: { value: '80' } });
    expect(slider).toHaveValue('80');
    expect(botonSellar()).toBeDisabled();

    await user.type(screen.getByRole('textbox'), 'Aparece en el KEV de CISA.');
    expect(botonSellar()).toBeEnabled();
  });

  it('manda la llamada, la certeza y el fundamento', async () => {
    vi.mocked(submitVerdict).mockResolvedValue({
      mission_id: 'MSN-TEST0001',
      call: 'MALICIOUS',
      confidence: 70,
      submitted_at: '',
      graded: true,
      brier_score: 0.09,
      xp_awarded: 64,
      was_correct: true,
      ground_truth: 'MALICIOUS',
      truth_source: 'KEV',
      message: '>> VEREDICTO CALIFICADO',
    });
    const { user, onSubmitted } = montar();
    await user.click(screen.getByRole('radio', { name: 'malicioso' }));
    await user.type(screen.getByRole('textbox'), 'ASN con antecedentes');
    await user.click(botonSellar());

    expect(submitVerdict).toHaveBeenCalledWith('MSN-TEST0001', {
      call: 'MALICIOUS',
      confidence: 70,
      rationale: 'ASN con antecedentes',
    });
    expect(onSubmitted).toHaveBeenCalledOnce();
  });

  it('muestra el rechazo del servidor tal cual', async () => {
    vi.mocked(submitVerdict).mockRejectedValue(
      new ApiRejection(409, 'Ya emitiste tu veredicto sobre esta misión.'),
    );
    const { user } = montar();
    await user.click(screen.getByRole('radio', { name: 'benigno' }));
    await user.click(botonSellar());
    expect(await screen.findByRole('alert')).toHaveTextContent('Ya emitiste tu veredicto');
  });

  it('una misión ya operada muestra el veredicto y no el formulario', () => {
    montar(
      mision({
        my_verdict: {
          call: 'MALICIOUS',
          confidence: 90,
          graded: true,
          xp_awarded: 96,
          was_correct: true,
          brier_score: 0.01,
        },
      }),
    );
    expect(screen.getByTestId('veredicto-calificado')).toHaveTextContent('+96 XP');
    expect(screen.queryByRole('button', { name: /sellar/i })).not.toBeInTheDocument();
  });

  it('un veredicto a ciegas figura como sellado, sin calificar', () => {
    montar(
      mision({
        awaiting_corroboration: true,
        independent_sources: 1,
        my_verdict: {
          call: 'BENIGN',
          confidence: 60,
          graded: false,
          xp_awarded: null,
          was_correct: null,
          brier_score: null,
        },
      }),
    );
    expect(screen.getByTestId('veredicto-sellado')).toHaveTextContent('1 de 2 operadores');
  });

  it('sin sesión no ofrece el formulario', () => {
    montar(mision(), false);
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
    expect(screen.getByText(/identificate/i)).toBeInTheDocument();
  });
});
