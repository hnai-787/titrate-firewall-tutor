using FirewallTutor.Models;
using FirewallTutor.Services;
using System.Data;

namespace FirewallTutor.Forms;

public sealed class MainForm : Form
{
    private readonly FirewallEngine _engine = new();

    private TabControl _tabs = new();

    private readonly DataGridView _rulesGrid = CreateGrid();
    private readonly DataGridView _packetsGrid = CreateGrid();
    private readonly DataGridView _resultsGrid = CreateGrid();
    private readonly TextBox _logsBox = new() { Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical };

    private readonly ComboBox _ruleField = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox _ruleValue = new();
    private readonly ComboBox _ruleAction = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox _ruleDescription = new();

    private readonly TextBox _srcIp = new() { Text = "192.168.10.15" };
    private readonly TextBox _dstIp = new() { Text = "1.1.1.1" };
    private readonly NumericUpDown _srcPort = new() { Minimum = 1, Maximum = 65535, Value = 2501 };
    private readonly NumericUpDown _dstPort = new() { Minimum = 1, Maximum = 65535, Value = 443 };
    private readonly ComboBox _protocol = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox _payload = new() { Text = "WEBREQUEST" };

    private readonly Label _dashboardStats = new() { AutoSize = true, Font = new Font("Segoe UI", 10), Padding = new Padding(0, 8, 0, 8) };
    private readonly Label _dashboardPolicy = new() { AutoSize = true, Font = new Font("Segoe UI", 10, FontStyle.Bold), Padding = new Padding(0, 8, 0, 8) };
    private readonly ComboBox _defaultActionSetting = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly CheckBox _autoRunSetting = new() { Text = "Auto-run simulation after data changes", AutoSize = true };
    private readonly CheckBox _loggingSetting = new() { Text = "Enable application logs", AutoSize = true, Checked = true };
    private readonly TextBox _outputPathSetting = new() { Text = "output/results.csv", Width = 260 };

    private bool _autoRunEnabled = false;
    private string _outputPath = "output/results.csv";

    public MainForm()
    {
        Text = "Firewall Tutor - OOP C#";
        Width = 1100;
        Height = 720;
        MinimumSize = new Size(900, 600);
        StartPosition = FormStartPosition.CenterScreen;

        _ruleField.Items.AddRange(Enum.GetNames(typeof(RuleField)));
        _ruleField.SelectedItem = nameof(RuleField.SourceIp);
        _ruleAction.Items.AddRange(Enum.GetNames(typeof(RuleAction)));
        _ruleAction.SelectedItem = nameof(RuleAction.Deny);
        _protocol.Items.AddRange(new object[] { "TCP", "UDP", "ICMP", "GRE" });
        _protocol.SelectedIndex = 0;

        _defaultActionSetting.Items.AddRange(Enum.GetNames(typeof(RuleAction)));
        _defaultActionSetting.SelectedItem = nameof(RuleAction.Deny);

        Controls.Add(BuildUi());

        _engine.LoadSampleRules();
        _engine.LoadSamplePackets();
        RefreshAll();
    }

    private Control BuildUi()
    {
        _tabs = new TabControl { Dock = DockStyle.Fill };

        _tabs.TabPages.Add(BuildHomeTab());
        _tabs.TabPages.Add(BuildRulesTab());
        _tabs.TabPages.Add(BuildPacketsTab());
        _tabs.TabPages.Add(BuildSimulationTab());
        _tabs.TabPages.Add(BuildLogsTab());
        _tabs.TabPages.Add(BuildTutorialTab());
        _tabs.TabPages.Add(BuildSettingsTab());
        _tabs.TabPages.Add(BuildAboutTab());

        return _tabs;
    }

    private TabPage BuildHomeTab()
    {
        TabPage page = new("Home");

        TableLayoutPanel layout = new()
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            Padding = new Padding(18)
        };

        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        Label title = new()
        {
            Text = "Firewall Tutor",
            AutoSize = true,
            Font = new Font("Segoe UI", 22, FontStyle.Bold)
        };

        Label subtitle = new()
        {
            Text = "A C# OOP learning project for firewall rules, simulated packets, and allow/deny decisions.",
            AutoSize = true,
            Font = new Font("Segoe UI", 11),
            Padding = new Padding(0, 4, 0, 12)
        };

        FlowLayoutPanel quickActions = new() { Dock = DockStyle.Top, AutoSize = true, WrapContents = true };
        quickActions.Controls.AddRange(new Control[]
        {
            Button("Load Sample Dataset", (_, _) => LoadSamples()),
            Button("Go to Rules", (_, _) => SelectTab("Rules")),
            Button("Go to Packets", (_, _) => SelectTab("Packets")),
            Button("Run Simulation", RunSimulation),
            Button("View Tutorial", (_, _) => SelectTab("Tutorial")),
            Button("Open Settings", (_, _) => SelectTab("Settings"))
        });

        GroupBox conceptBox = new()
        {
            Text = "How the simulation works",
            Dock = DockStyle.Top,
            AutoSize = true,
            Padding = new Padding(12)
        };

        Label conceptText = new()
        {
            AutoSize = true,
            Text = "1. Create firewall rules.\n" +
                   "2. Create or load simulated packets.\n" +
                   "3. Run the simulation.\n" +
                   "4. The first matching rule is applied.\n" +
                   "5. If no rule matches, the selected default policy is used."
        };
        conceptBox.Controls.Add(conceptText);

        _dashboardPolicy.Text = "Default Policy: DENY";
        RefreshDashboard();

        layout.Controls.Add(title, 0, 0);
        layout.Controls.Add(subtitle, 0, 1);
        layout.Controls.Add(quickActions, 0, 2);
        layout.Controls.Add(_dashboardPolicy, 0, 3);
        layout.Controls.Add(_dashboardStats, 0, 4);
        layout.Controls.Add(conceptBox, 0, 5);

        page.Controls.Add(layout);
        return page;
    }

    private TabPage BuildRulesTab()
    {
        TabPage page = new("Rules");
        TableLayoutPanel layout = new() { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(10) };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        layout.Controls.Add(new Label { Text = "Create firewall rules. Rules are checked from top to bottom. First match wins.", AutoSize = true }, 0, 0);

        FlowLayoutPanel form = new() { Dock = DockStyle.Top, AutoSize = true, WrapContents = true };
        form.Controls.AddRange(new Control[]
        {
            LabelFor("Field"), _ruleField,
            LabelFor("Value"), Sized(_ruleValue, 160),
            LabelFor("Action"), _ruleAction,
            LabelFor("Description"), Sized(_ruleDescription, 260),
            Button("Add Rule", AddRule),
            Button("Remove Selected", RemoveSelectedRule),
            Button("Load Samples", (_, _) => { _engine.LoadSampleRules(); AfterDataChanged(); }),
            Button("Save Rules CSV", SaveRules)
        });
        layout.Controls.Add(form, 0, 1);
        layout.Controls.Add(_rulesGrid, 0, 2);
        page.Controls.Add(layout);
        return page;
    }

    private TabPage BuildPacketsTab()
    {
        TabPage page = new("Packets");
        TableLayoutPanel layout = new() { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(10) };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label { Text = "Create simulated packets for firewall inspection.", AutoSize = true }, 0, 0);

        FlowLayoutPanel form = new() { Dock = DockStyle.Top, AutoSize = true, WrapContents = true };
        form.Controls.AddRange(new Control[]
        {
            LabelFor("SRC IP"), Sized(_srcIp, 120),
            LabelFor("DST IP"), Sized(_dstIp, 120),
            LabelFor("SRC Port"), _srcPort,
            LabelFor("DST Port"), _dstPort,
            LabelFor("Protocol"), _protocol,
            LabelFor("Payload"), Sized(_payload, 160),
            Button("Add Packet", AddPacket),
            Button("Remove Selected", RemoveSelectedPacket),
            Button("Load Samples", (_, _) => { _engine.LoadSamplePackets(); AfterDataChanged(); }),
            Button("Save Packets CSV", SavePackets)
        });
        layout.Controls.Add(form, 0, 1);
        layout.Controls.Add(_packetsGrid, 0, 2);
        page.Controls.Add(layout);
        return page;
    }

    private TabPage BuildSimulationTab()
    {
        TabPage page = new("Simulation");
        TableLayoutPanel layout = new() { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(10) };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        FlowLayoutPanel buttons = new() { AutoSize = true, Dock = DockStyle.Top };
        buttons.Controls.Add(Button("Run Simulation", RunSimulation));
        buttons.Controls.Add(Button("Export Results CSV", SaveResults));
        buttons.Controls.Add(new Label { Text = "Default policy is configurable in Settings.", AutoSize = true, Padding = new Padding(15, 8, 0, 0) });
        layout.Controls.Add(buttons, 0, 0);
        layout.Controls.Add(_resultsGrid, 0, 1);
        page.Controls.Add(layout);
        return page;
    }

    private TabPage BuildLogsTab()
    {
        TabPage page = new("Logs");
        TableLayoutPanel layout = new() { Dock = DockStyle.Fill, RowCount = 2, Padding = new Padding(10) };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, AutoSize = true };
        buttons.Controls.Add(Button("Refresh Logs", (_, _) => RefreshLogs()));
        buttons.Controls.Add(Button("Clear Logs", (_, _) => { _engine.ClearLogs(); RefreshLogs(); }));
        layout.Controls.Add(buttons, 0, 0);
        layout.Controls.Add(_logsBox, 0, 1);

        page.Controls.Add(layout);
        return page;
    }

    private static TabPage BuildTutorialTab()
    {
        TabPage page = new("Tutorial");
        TextBox box = new()
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Text = "Firewall Tutor Tutorial\r\n\r\n" +
                   "1. Use the Home tab to load sample data or start quickly.\r\n" +
                   "2. Add rules in the Rules tab.\r\n" +
                   "3. Add packets in the Packets tab.\r\n" +
                   "4. Run the simulation in the Simulation tab.\r\n" +
                   "5. Configure default policy, logging, and output path in Settings.\r\n\r\n" +
                   "Supported rule fields:\r\n" +
                   "- Any\r\n- SourceIp\r\n- DestinationIp\r\n- SourcePort\r\n- DestinationPort\r\n- Protocol\r\n- PayloadContains\r\n\r\n" +
                   "Supported IP examples:\r\n" +
                   "- Exact: 10.0.0.5\r\n" +
                   "- Last-octet range: 192.168.1.10-20\r\n" +
                   "- CIDR: 172.16.5.0/24\r\n\r\n" +
                   "Security concept:\r\n" +
                   "Rules are checked in order. The first matching rule wins. If no rule matches, the selected default policy is applied."
        };
        page.Controls.Add(box);
        return page;
    }

    private TabPage BuildSettingsTab()
    {
        TabPage page = new("Settings");

        TableLayoutPanel layout = new()
        {
            Dock = DockStyle.Top,
            ColumnCount = 2,
            RowCount = 5,
            Padding = new Padding(18),
            AutoSize = true
        };

        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        layout.Controls.Add(LabelFor("Default Policy"), 0, 0);
        layout.Controls.Add(_defaultActionSetting, 1, 0);

        layout.Controls.Add(LabelFor("Automation"), 0, 1);
        layout.Controls.Add(_autoRunSetting, 1, 1);

        layout.Controls.Add(LabelFor("Logging"), 0, 2);
        layout.Controls.Add(_loggingSetting, 1, 2);

        layout.Controls.Add(LabelFor("Output CSV Path"), 0, 3);
        layout.Controls.Add(_outputPathSetting, 1, 3);

        FlowLayoutPanel buttons = new() { AutoSize = true };
        buttons.Controls.Add(Button("Apply Settings", ApplySettings));
        buttons.Controls.Add(Button("Reset Defaults", ResetSettings));
        layout.Controls.Add(buttons, 1, 4);

        page.Controls.Add(layout);
        return page;
    }

    private static TabPage BuildAboutTab()
    {
        TabPage page = new("About");
        Label label = new()
        {
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleCenter,
            Font = new Font("Segoe UI", 12),
            Text = "Firewall Tutor\n\nObject Oriented Programming Project\nC# Windows Forms\n\nEducational firewall simulation.\nIt does not inspect or block real network traffic."
        };
        page.Controls.Add(label);
        return page;
    }

    private void AddRule(object? sender, EventArgs e)
    {
        try
        {
            int id = _engine.Rules.Count == 0 ? 1 : _engine.Rules.Max(r => r.Id) + 1;
            RuleField field = Enum.Parse<RuleField>(_ruleField.Text);
            RuleAction action = Enum.Parse<RuleAction>(_ruleAction.Text);
            _engine.AddRule(new FirewallRule(id, field, _ruleValue.Text, action, _ruleDescription.Text));
            AfterDataChanged();
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
    }

    private void RemoveSelectedRule(object? sender, EventArgs e)
    {
        if (_rulesGrid.CurrentRow?.DataBoundItem is FirewallRule rule)
        {
            _engine.RemoveRule(rule.Id);
            AfterDataChanged();
        }
    }

    private void AddPacket(object? sender, EventArgs e)
    {
        try
        {
            int id = _engine.Packets.Count == 0 ? 1 : _engine.Packets.Max(p => p.Id) + 1;
            _engine.AddPacket(new NetworkPacket(id, _srcIp.Text, _dstIp.Text, (int)_srcPort.Value, (int)_dstPort.Value, _protocol.Text, _payload.Text));
            AfterDataChanged();
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
    }

    private void RemoveSelectedPacket(object? sender, EventArgs e)
    {
        if (_packetsGrid.CurrentRow?.DataBoundItem is NetworkPacket packet)
        {
            _engine.RemovePacket(packet.Id);
            AfterDataChanged();
        }
    }

    private void RunSimulation(object? sender, EventArgs e)
    {
        _resultsGrid.DataSource = _engine.EvaluateAll();
        RefreshLogs();
        RefreshDashboard();
        SelectTab("Simulation");
    }

    private void SaveRules(object? sender, EventArgs e)
    {
        CsvStorage.SaveRules("data/rules.csv", _engine.Rules);
        MessageBox.Show("Rules saved to data/rules.csv", "Saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void SavePackets(object? sender, EventArgs e)
    {
        CsvStorage.SavePackets("data/packets.csv", _engine.Packets);
        MessageBox.Show("Packets saved to data/packets.csv", "Saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void SaveResults(object? sender, EventArgs e)
    {
        List<EvaluationResult> results = _engine.EvaluateAll();
        CsvStorage.SaveResults(_outputPath, results);
        _resultsGrid.DataSource = results;
        RefreshLogs();
        RefreshDashboard();
        MessageBox.Show($"Results saved to {_outputPath}", "Saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ApplySettings(object? sender, EventArgs e)
    {
        _engine.DefaultAction = Enum.Parse<RuleAction>(_defaultActionSetting.Text);
        _engine.LoggingEnabled = _loggingSetting.Checked;
        _autoRunEnabled = _autoRunSetting.Checked;
        _outputPath = string.IsNullOrWhiteSpace(_outputPathSetting.Text) ? "output/results.csv" : _outputPathSetting.Text.Trim();
        RefreshDashboard();
        MessageBox.Show("Settings applied.", "Settings", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ResetSettings(object? sender, EventArgs e)
    {
        _defaultActionSetting.SelectedItem = nameof(RuleAction.Deny);
        _autoRunSetting.Checked = false;
        _loggingSetting.Checked = true;
        _outputPathSetting.Text = "output/results.csv";
        ApplySettings(sender, e);
    }

    private void LoadSamples()
    {
        _engine.LoadSampleRules();
        _engine.LoadSamplePackets();
        AfterDataChanged();
        SelectTab("Rules");
    }

    private void AfterDataChanged()
    {
        RefreshAll();
        if (_autoRunEnabled)
        {
            _resultsGrid.DataSource = _engine.EvaluateAll();
            RefreshLogs();
        }
    }

    private void RefreshAll()
    {
        _rulesGrid.DataSource = null;
        _rulesGrid.DataSource = _engine.Rules.ToList();

        _packetsGrid.DataSource = null;
        _packetsGrid.DataSource = _engine.Packets.ToList();

        RefreshLogs();
        RefreshDashboard();
    }

    private void RefreshLogs()
    {
        _logsBox.Text = string.Join(Environment.NewLine, _engine.Logs.Reverse());
    }

    private void RefreshDashboard()
    {
        int resultCount = 0;
        int allowCount = 0;
        int denyCount = 0;

        if (_resultsGrid.DataSource is IEnumerable<EvaluationResult> results)
        {
            List<EvaluationResult> list = results.ToList();
            resultCount = list.Count;
            allowCount = list.Count(r => r.FinalAction == RuleAction.Allow);
            denyCount = list.Count(r => r.FinalAction == RuleAction.Deny);
        }

        _dashboardPolicy.Text = $"Default Policy: {_engine.DefaultAction.ToString().ToUpperInvariant()} | Logging: {(_engine.LoggingEnabled ? "ON" : "OFF")} | Auto-run: {(_autoRunEnabled ? "ON" : "OFF")}";
        _dashboardStats.Text = $"Rules loaded: {_engine.Rules.Count}\n" +
                               $"Packets loaded: {_engine.Packets.Count}\n" +
                               $"Last simulation results: {resultCount}\n" +
                               $"Allowed: {allowCount}\n" +
                               $"Denied: {denyCount}\n" +
                               $"Output path: {_outputPath}";
    }

    private void SelectTab(string title)
    {
        foreach (TabPage page in _tabs.TabPages)
        {
            if (string.Equals(page.Text, title, StringComparison.OrdinalIgnoreCase))
            {
                _tabs.SelectedTab = page;
                return;
            }
        }
    }

    private static DataGridView CreateGrid()
    {
        return new DataGridView
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false
        };
    }

    private static Label LabelFor(string text) => new() { Text = text + ":", AutoSize = true, Padding = new Padding(8, 8, 0, 0) };

    private static TextBox Sized(TextBox box, int width)
    {
        box.Width = width;
        return box;
    }

    private static Button Button(string text, EventHandler handler)
    {
        Button button = new() { Text = text, AutoSize = true, Margin = new Padding(8) };
        button.Click += handler;
        return button;
    }

    private static void ShowError(string message)
    {
        MessageBox.Show(message, "Input Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }
}
