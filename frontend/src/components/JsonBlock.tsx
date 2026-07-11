type Props = {
  data: unknown;
};

export function JsonBlock({ data }: Props) {
  return <pre className="json-block">{JSON.stringify(data, null, 2)}</pre>;
}
