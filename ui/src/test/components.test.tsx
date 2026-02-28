import { describe, it, expect } from 'vitest';
import React from 'react';
import { render, screen } from '@testing-library/react';
import { Badge, ConfidenceBadge, QueueBadge, ScoreBadge, StatusBadge } from '../components/Badge';
import { Button } from '../components/Button';
import { Card, KpiTile } from '../components/Card';
import { EmptyState, LoadingSpinner, ErrorPanel } from '../components/States';

describe('Badge', () => {
  it('renders children', () => {
    render(<Badge>test</Badge>);
    expect(screen.getByText('test')).toBeInTheDocument();
  });

  it('applies variant classes', () => {
    render(<Badge variant="danger">critical</Badge>);
    const el = screen.getByText('critical');
    expect(el.className).toContain('red');
  });
});

describe('ConfidenceBadge', () => {
  it('renders high as danger', () => {
    render(<ConfidenceBadge confidence="high" />);
    const el = screen.getByText('high');
    expect(el.className).toContain('red');
  });

  it('renders medium as warning', () => {
    render(<ConfidenceBadge confidence="medium" />);
    const el = screen.getByText('medium');
    expect(el.className).toContain('yellow');
  });

  it('renders low as muted', () => {
    render(<ConfidenceBadge confidence="low" />);
    expect(screen.getByText('low')).toBeInTheDocument();
  });
});

describe('QueueBadge', () => {
  it('strips soc_ prefix in display', () => {
    render(<QueueBadge queue="soc_malware" />);
    expect(screen.getByText('malware')).toBeInTheDocument();
  });
});

describe('ScoreBadge', () => {
  it('renders score value', () => {
    render(<ScoreBadge score={92} />);
    expect(screen.getByText('92')).toBeInTheDocument();
  });

  it('uses danger for high scores', () => {
    render(<ScoreBadge score={85} />);
    const wrapper = screen.getByText('85').closest('span[title]')!;
    expect(wrapper.className).toContain('red');
  });
});

describe('StatusBadge', () => {
  it('renders status', () => {
    render(<StatusBadge status="success" />);
    expect(screen.getByText('success')).toBeInTheDocument();
  });
});

describe('Button', () => {
  it('renders children', () => {
    render(<Button>Click Me</Button>);
    expect(screen.getByText('Click Me')).toBeInTheDocument();
  });

  it('disables when loading', () => {
    render(<Button loading>Loading</Button>);
    expect(screen.getByRole('button')).toBeDisabled();
  });
});

describe('Card', () => {
  it('renders title and children', () => {
    render(<Card title="Test Card"><p>Content</p></Card>);
    expect(screen.getByText('Test Card')).toBeInTheDocument();
    expect(screen.getByText('Content')).toBeInTheDocument();
  });
});

describe('KpiTile', () => {
  it('renders label and value', () => {
    render(<KpiTile label="Total" value={42} />);
    expect(screen.getByText('Total')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
  });
});

describe('States', () => {
  it('renders loading spinner', () => {
    render(<LoadingSpinner label="Loading test..." />);
    expect(screen.getByText('Loading test...')).toBeInTheDocument();
  });

  it('renders empty state', () => {
    render(<EmptyState title="Nothing here" description="Try again" />);
    expect(screen.getByText('Nothing here')).toBeInTheDocument();
    expect(screen.getByText('Try again')).toBeInTheDocument();
  });

  it('renders error panel', () => {
    render(<ErrorPanel message="Something went wrong" />);
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
  });
});
