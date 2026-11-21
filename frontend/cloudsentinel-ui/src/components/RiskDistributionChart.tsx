import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type Props = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
};

export default function RiskDistributionChart(props: Props) {
  const data = [
    { name: "Critical", count: props.critical },
    { name: "High", count: props.high },
    { name: "Medium", count: props.medium },
    { name: "Low", count: props.low },
    { name: "Info", count: props.informational },
  ];
  const colors = ["#ff9393", "#e7b277", "#f0c36e", "#78d9b0", "#9ebbd0"];

  return (
    <div
      className="risk-chart"
      role="img"
      aria-label={`Active findings by risk: ${props.critical} critical, ${props.high} high, ${props.medium} medium, ${props.low} low, ${props.informational} informational`}
    >
      <ResponsiveContainer width="100%" height={175}>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 3, right: 16, bottom: 3, left: 0 }}
        >
          <XAxis type="number" hide allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="name"
            width={82}
            tick={{ fill: "#82919e", fontSize: 10 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            cursor={{ fill: "#1a3942" }}
            contentStyle={{
              background: "#111a22",
              border: "1px solid #293741",
              borderRadius: 7,
              color: "#e7edf2",
              fontSize: 10,
            }}
          />
          <Bar
            dataKey="count"
            name="Findings"
            radius={[0, 3, 3, 0]}
            maxBarSize={15}
          >
            {colors.map((fill, index) => (
              <Cell key={index} fill={fill} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
