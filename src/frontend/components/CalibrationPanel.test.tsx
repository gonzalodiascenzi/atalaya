import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import CalibrationPanel from './CalibrationPanel';

describe('CalibrationPanel', () => {
  it('sin veredictos invita a emitir el primero', () => {
    render(<CalibrationPanel data={null} />);
    expect(screen.getByTestId('panel-calibracion')).toHaveTextContent(/emití tu primero/i);
  });

  it('avisa de los veredictos que esperan corroboración', () => {
    render(
      <CalibrationPanel
        data={{
          callsign: 'gon',
          verdicts_graded: 0,
          verdicts_pending: 2,
          calibration: null,
          mean_brier: null,
          accuracy: null,
          mean_confidence: null,
          overconfidence: null,
        }}
      />,
    );
    expect(screen.getByTestId('panel-calibracion')).toHaveTextContent(/2 sellados/i);
  });

  it('marca la sobreconfianza', () => {
    render(
      <CalibrationPanel
        data={{
          callsign: 'gon',
          verdicts_graded: 10,
          verdicts_pending: 0,
          calibration: 0.62,
          mean_brier: 0.38,
          accuracy: 0.5,
          mean_confidence: 88,
          overconfidence: 0.38,
        }}
      />,
    );
    const panel = screen.getByTestId('panel-calibracion');
    expect(panel).toHaveTextContent('0.62');
    expect(panel).toHaveTextContent('+38 pts');
    expect(panel).toHaveTextContent(/creés saber bastante más/i);
  });
});
