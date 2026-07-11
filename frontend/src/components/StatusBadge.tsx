type Props = {
  value: string;
};

export function StatusBadge({ value }: Props) {
  const tone = value === "ok" || value === "configured" ? "good" : value === "empty" ? "warn" : "bad";
  return <span className={`status ${tone}`}>{value}</span>;
}
