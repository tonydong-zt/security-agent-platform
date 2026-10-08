import ReactMarkdown from 'react-markdown';
import rehypeSanitize from 'rehype-sanitize';
import remarkGfm from 'remark-gfm';
import type { ChartDatum, ChartSpec } from './api';

const chartMarker = /<!--\s*chart:([a-z0-9-]+)\s*-->/gi;

export function ReportRenderer({ markdown, charts }: { markdown: string; charts: ChartSpec[] }) {
  const parts = markdown.split(chartMarker);
  const chartMap = new Map(charts.map((chart) => [chart.id, chart]));
  return (
    <article className="markdown-report">
      {parts.map((part, index) => {
        if (index % 2 === 1) {
          const chart = chartMap.get(part);
          return chart ? <ChartCard key={`chart-${part}`} chart={chart} /> : null;
        }
        if (!part.trim()) return null;
        return (
          <ReactMarkdown
            key={`markdown-${index}`}
            remarkPlugins={[remarkGfm]}
            rehypePlugins={[rehypeSanitize]}
            components={{
              table: ({ children, ...props }) => (
                <div className="table-scroll">
                  <table {...props}>{children}</table>
                </div>
              ),
              a: ({ children, ...props }) => (
                <a {...props} target="_blank" rel="noreferrer noopener">
                  {children}
                </a>
              ),
            }}
          >
            {part}
          </ReactMarkdown>
        );
      })}
    </article>
  );
}

export function ChartCard({ chart }: { chart: ChartSpec }) {
  return (
    <figure className={`report-chart chart-${chart.type}`} aria-label={chart.title}>
      <figcaption>
        <div>
          <b>{chart.title}</b>
          <small>{chart.subtitle}</small>
        </div>
        <span>AGENT CHART</span>
      </figcaption>
      {chart.type === 'bar' && <BarChart data={chart.data ?? []} />}
      {chart.type === 'donut' && <DonutChart data={chart.data ?? []} />}
      {chart.type === 'timeline' && <TimelineChart chart={chart} />}
    </figure>
  );
}

function BarChart({ data }: { data: ChartDatum[] }) {
  return (
    <div className="bar-chart" role="img" aria-label="风险维度横向条形图">
      {data.map((item) => (
        <div className="bar-row" key={item.label}>
          <span>{item.label}</span>
          <div className="bar-track">
            <i style={{ width: `${clamp(item.value)}%`, background: safeColor(item.color) }} />
          </div>
          <b>{item.value}</b>
        </div>
      ))}
    </div>
  );
}

function DonutChart({ data }: { data: ChartDatum[] }) {
  const total = data.reduce((sum, item) => sum + Math.max(0, item.value), 0);
  let cursor = 0;
  const segments = data.map((item) => {
    const start = cursor;
    cursor += total ? (Math.max(0, item.value) / total) * 100 : 0;
    return `${safeColor(item.color)} ${start}% ${cursor}%`;
  });
  const background = segments.length ? `conic-gradient(${segments.join(',')})` : '#26344a';
  return (
    <div className="donut-layout" role="img" aria-label="分类占比环形图">
      <div className="donut" style={{ background }}>
        <div>
          <b>{total}</b>
          <small>总计</small>
        </div>
      </div>
      <div className="chart-legend">
        {data.map((item) => (
          <div key={item.label}>
            <i style={{ background: safeColor(item.color) }} />
            <span>{item.label}</span>
            <b>{item.value}</b>
          </div>
        ))}
      </div>
    </div>
  );
}

function TimelineChart({ chart }: { chart: ChartSpec }) {
  return (
    <div className="timeline-chart">
      {(chart.events ?? []).map((event, index) => (
        <div className="timeline-event" key={`${event.time}-${event.source}`}>
          <i>{index + 1}</i>
          <div>
            <time>{event.time}</time>
            <b>{event.label}</b>
            <small>{event.source}</small>
          </div>
        </div>
      ))}
    </div>
  );
}

function clamp(value: number): number {
  return Math.max(0, Math.min(100, value));
}

function safeColor(value?: string): string {
  return value && /^#[0-9a-f]{6}$/i.test(value) ? value : '#6f9dff';
}
