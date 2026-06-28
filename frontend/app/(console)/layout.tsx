import EnterpriseLayout from "@/components/layout/EnterpriseLayout";

export default function ConsoleLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <EnterpriseLayout>{children}</EnterpriseLayout>;
}
