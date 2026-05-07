package tech.cybersword.tls.fuzzer.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Image;
import java.awt.GraphicsEnvironment;
import java.awt.GridLayout;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

import javax.imageio.ImageIO;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;

import tech.cybersword.tls.fuzzer.common.CommonProperties;
import tech.cybersword.tls.fuzzer.controller.TLSController;
import tech.cybersword.tls.fuzzer.controller.TLSController.TestSuite;
import tech.cybersword.tls.fuzzer.dashboard.FuzzerStatusRegistry;
import tech.cybersword.tls.fuzzer.dashboard.FuzzerTestStatus;
import tech.cybersword.tls.fuzzer.dashboard.TLSHandshakeFlows;
import tech.cybersword.tls.fuzzer.dashboard.TLSHandshakeStep;
import tech.cybersword.tls.fuzzer.dashboard.TLSHandshakeStepStatus;

public class TLSDashboard {

	private static final Color BACKGROUND = new Color(2, 6, 4);
	private static final Color PANEL_BACKGROUND = new Color(1, 18, 8, 218);
	private static final Color GRID_GREEN = new Color(21, 128, 61);
	private static final Color TEXT_GREEN = new Color(141, 255, 178);
	private static final Color ACCENT = new Color(217, 255, 95);
	private static final Color CYAN = new Color(103, 232, 249);
	private static final Color DANGER = new Color(255, 106, 106);
	private static final Font MONO = new Font(Font.MONOSPACED, Font.PLAIN, 12);
	private static final Font MONO_BOLD = new Font(Font.MONOSPACED, Font.BOLD, 12);

	private static TLSDashboard instance;

	private JFrame frame;
	private StatusTableModel tableModel;
	private FlowTableModel flowTableModel;
	private JTextField hostField;
	private JTextField portField;
	private JTextArea logArea;
	private JTextArea agentArea;

	public static TLSDashboard getInstance() {
		if (instance == null) {
			instance = new TLSDashboard();
		}
		return instance;
	}

	private TLSDashboard() {
	}

	public void show() {
		if (GraphicsEnvironment.isHeadless()) {
			return;
		}
		SwingUtilities.invokeLater(() -> {
			if (frame == null) {
				initFrame();
			}
			tableModel.refresh();
			flowTableModel.refresh();
			frame.setVisible(true);
			frame.toFront();
		});
	}

	private void initFrame() {
		tableModel = new StatusTableModel();
		JTable table = new JTable(tableModel);
		styleTable(table, new TerminalCellRenderer(), 24);

		flowTableModel = new FlowTableModel();
		JTable flowTable = new JTable(flowTableModel);
		styleTable(flowTable, new FlowCellRenderer(), 28);

		logArea = new JTextArea();
		logArea.setEditable(false);
		logArea.setRows(8);
		logArea.setFont(MONO);
		logArea.setBackground(BACKGROUND);
		logArea.setForeground(CYAN);
		logArea.setCaretColor(TEXT_GREEN);
		logArea.setBorder(new EmptyBorder(10, 10, 10, 10));
		agentArea = new JTextArea();
		agentArea.setEditable(false);
		agentArea.setRows(12);
		agentArea.setFont(MONO);
		agentArea.setBackground(BACKGROUND);
		agentArea.setForeground(CYAN);
		agentArea.setCaretColor(TEXT_GREEN);
		agentArea.setBorder(new EmptyBorder(10, 10, 10, 10));
		hostField = new JTextField(CommonProperties.getInstance().getTlsHost());
		portField = new JTextField(String.valueOf(CommonProperties.getInstance().getTlsPort()));
		styleField(hostField);
		styleField(portField);

		frame = new JFrame("TLS Fuzzer Dashboard");
		frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
		BackgroundPanel backgroundPanel = new BackgroundPanel();
		backgroundPanel.setLayout(new BorderLayout());
		frame.setContentPane(backgroundPanel);
		JPanel topPanel = new JPanel(new BorderLayout());
		topPanel.setBackground(PANEL_BACKGROUND);
		topPanel.add(createHeaderPanel(), BorderLayout.NORTH);
		topPanel.add(createControlPanel(), BorderLayout.CENTER);
		frame.add(topPanel, BorderLayout.NORTH);

		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, terminalScroll(table), terminalScroll(logArea));
		splitPane.setBorder(new EmptyBorder(10, 12, 12, 12));
		splitPane.setBackground(BACKGROUND);
		splitPane.setDividerLocation(390);

		JTabbedPane tabs = new JTabbedPane();
		tabs.setFont(MONO_BOLD);
		tabs.setBackground(PANEL_BACKGROUND);
		tabs.setForeground(TEXT_GREEN);
		tabs.addTab("Test Status / Logs", splitPane);
		tabs.addTab("TLS 1.2 / TLS 1.3 Flow", terminalScroll(flowTable));
		tabs.addTab("TLS Agent", terminalScroll(agentArea));
		frame.add(tabs, BorderLayout.CENTER);
		frame.setSize(1240, 760);
		frame.setLocationRelativeTo(null);

		Timer timer = new Timer(1000, e -> refresh());
		timer.start();
	}

	private void styleTable(JTable table, DefaultTableCellRenderer renderer, int rowHeight) {
		table.setFillsViewportHeight(true);
		table.setFont(MONO);
		table.setRowHeight(rowHeight);
		table.setBackground(BACKGROUND);
		table.setForeground(TEXT_GREEN);
		table.setGridColor(new Color(34, 197, 94, 70));
		table.setSelectionBackground(new Color(6, 61, 32));
		table.setSelectionForeground(ACCENT);
		table.setDefaultRenderer(Object.class, renderer);
		JTableHeader header = table.getTableHeader();
		header.setBackground(new Color(8, 40, 20));
		header.setForeground(ACCENT);
		header.setFont(MONO_BOLD);
	}

	private JPanel createHeaderPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBackground(PANEL_BACKGROUND);
		panel.setBorder(new EmptyBorder(14, 16, 8, 16));
		JLabel title = new JLabel("root@tls-fuzzer:~$ TLS Fuzzer Dashboard");
		title.setForeground(ACCENT);
		title.setFont(new Font(Font.MONOSPACED, Font.BOLD, 18));
		JLabel brand = new JLabel("https://cybersword.tech");
		brand.setForeground(CYAN);
		brand.setFont(MONO_BOLD);
		panel.add(title, BorderLayout.WEST);
		panel.add(brand, BorderLayout.EAST);
		return panel;
	}

	private static class BackgroundPanel extends JPanel {

		private static final long serialVersionUID = 1L;
		private final Image backgroundImage;

		BackgroundPanel() {
			setBackground(BACKGROUND);
			backgroundImage = loadBackgroundImage();
		}

		@Override
		protected void paintComponent(Graphics graphics) {
			super.paintComponent(graphics);
			if (backgroundImage == null) {
				return;
			}
			int panelWidth = getWidth();
			int panelHeight = getHeight();
			int imageWidth = backgroundImage.getWidth(this);
			int imageHeight = backgroundImage.getHeight(this);
			if (panelWidth <= 0 || panelHeight <= 0 || imageWidth <= 0 || imageHeight <= 0) {
				return;
			}
			double scale = Math.max((double) panelWidth / imageWidth, (double) panelHeight / imageHeight);
			int scaledWidth = (int) Math.ceil(imageWidth * scale);
			int scaledHeight = (int) Math.ceil(imageHeight * scale);
			int x = (panelWidth - scaledWidth) / 2;
			int y = (panelHeight - scaledHeight) / 2;
			graphics.drawImage(backgroundImage, x, y, scaledWidth, scaledHeight, this);
			graphics.setColor(new Color(2, 6, 4, 176));
			graphics.fillRect(0, 0, panelWidth, panelHeight);
		}

		private Image loadBackgroundImage() {
			try {
				return ImageIO.read(Path.of("pics", "CS_v.png").toFile());
			} catch (IOException e) {
				return null;
			}
		}
	}

	private JPanel createControlPanel() {
		JPanel panel = new JPanel(new GridLayout(2, 8, 8, 6));
		panel.setBackground(PANEL_BACKGROUND);
		panel.setBorder(new EmptyBorder(8, 16, 14, 16));
		panel.add(new JLabel("Target IP / Host"));
		panel.add(new JLabel("Port"));
		for (int i = 0; i < 6; i++) {
			panel.add(new JLabel(""));
		}
		for (Component component : panel.getComponents()) {
			if (component instanceof JLabel label) {
				label.setForeground(new Color(101, 217, 139));
				label.setFont(MONO_BOLD);
			}
		}
		panel.add(hostField);
		panel.add(portField);
		panel.add(button("Start All", TestSuite.ALL));
		panel.add(button("TLS 1.2", TestSuite.TLS12));
		panel.add(button("TLS 1.3", TestSuite.TLS13));
		panel.add(button("RFC", TestSuite.RFC));
		panel.add(button("Random", TestSuite.RANDOM));

		JButton stopButton = new JButton("End Tests");
		stopButton.addActionListener(e -> TLSController.getInstance().stopTests());
		styleButton(stopButton, DANGER);
		panel.add(stopButton);
		return panel;
	}

	private JButton button(String label, TestSuite suite) {
		JButton button = new JButton(label);
		button.addActionListener(e -> TLSController.getInstance().startTests(hostField.getText(), parsePort(), suite));
		styleButton(button, TEXT_GREEN);
		return button;
	}

	private void styleField(JTextField field) {
		field.setFont(MONO);
		field.setBackground(BACKGROUND);
		field.setForeground(TEXT_GREEN);
		field.setCaretColor(TEXT_GREEN);
		field.setBorder(javax.swing.BorderFactory.createCompoundBorder(
				javax.swing.BorderFactory.createLineBorder(GRID_GREEN),
				javax.swing.BorderFactory.createEmptyBorder(5, 8, 5, 8)));
	}

	private void styleButton(JButton button, Color foreground) {
		button.setFont(MONO_BOLD);
		button.setBackground(BACKGROUND);
		button.setForeground(foreground);
		button.setFocusPainted(false);
		button.setBorder(javax.swing.BorderFactory.createCompoundBorder(
				javax.swing.BorderFactory.createLineBorder(foreground),
				javax.swing.BorderFactory.createEmptyBorder(5, 8, 5, 8)));
	}

	private JScrollPane terminalScroll(Component component) {
		JScrollPane scrollPane = new JScrollPane(component);
		scrollPane.setBackground(BACKGROUND);
		scrollPane.getViewport().setBackground(BACKGROUND);
		scrollPane.setBorder(javax.swing.BorderFactory.createLineBorder(GRID_GREEN));
		return scrollPane;
	}

	private int parsePort() {
		try {
			return Integer.parseInt(portField.getText());
		} catch (NumberFormatException e) {
			return CommonProperties.getInstance().getTlsPort();
		}
	}

	private void refresh() {
		tableModel.refresh();
		flowTableModel.refresh();
		List<String> logs = FuzzerStatusRegistry.getInstance().serverResponseLogSnapshot();
		int fromIndex = Math.max(0, logs.size() - 120);
		if (logs.isEmpty()) {
			logArea.setText("No server responses with bytes yet. Hidden NO_RESPONSE entries: "
					+ FuzzerStatusRegistry.getInstance().noResponseLogCount()
					+ ". Full request and no-response evidence is still written to log files.");
		} else {
			logArea.setText(String.join(System.lineSeparator(), logs.subList(fromIndex, logs.size())));
		}
		agentArea.setText(agentView(logs));
	}

	private String agentView(List<String> serverResponses) {
		List<FuzzerTestStatus> statuses = FuzzerStatusRegistry.getInstance().snapshot();
		List<TLSHandshakeStepStatus> steps = FuzzerStatusRegistry.getInstance().handshakeStepSnapshot();
		long runningJobs = statuses.stream().filter(status -> status.getState() == FuzzerTestStatus.State.RUNNING).count();
		long executedJobs = statuses.stream().filter(status -> status.getState() == FuzzerTestStatus.State.EXECUTED).count();
		long failedJobs = statuses.stream().filter(status -> status.getState() == FuzzerTestStatus.State.FAILED).count();
		TLSHandshakeStepStatus activeStep = steps.isEmpty() ? null : steps.get(steps.size() - 1);
		String latestResponse = serverResponses.isEmpty() ? "no server responses with bytes yet"
				: serverResponses.get(serverResponses.size() - 1);
		return String.join(System.lineSeparator(),
				"TLS Agent",
				"",
				"Target: " + TLSController.getInstance().getTargetHost() + ":" + TLSController.getInstance().getTargetPort(),
				"Suite: " + TLSController.getInstance().getActiveSuite(),
				"Agent state: " + (TLSController.getInstance().isRunning() ? "RUNNING" : "IDLE"),
				"Jobs: " + statuses.size() + " total | " + runningJobs + " running | " + executedJobs
						+ " executed | " + failedJobs + " failed",
				"Active TLS step: " + formatActiveStep(activeStep),
				"Visible server responses: " + serverResponses.size(),
				"Hidden NO_RESPONSE entries: " + FuzzerStatusRegistry.getInstance().noResponseLogCount(),
				"",
				"Components:",
				"- Target and suite coordinator",
				"- TLS 1.2 / TLS 1.3 flow observer",
				"- Payload sender and server-response classifier",
				"- Execution counters",
				"- Latest server response",
				"",
				"Latest server response:",
				latestResponse);
	}

	private String formatActiveStep(TLSHandshakeStepStatus status) {
		if (status == null) {
			return "-";
		}
		return status.protocol() + " step " + status.sequence() + " | " + status.state() + " | " + status.jobName()
				+ " #" + status.iteration() + " | " + status.responseSummary();
	}

	private static class StatusTableModel extends AbstractTableModel {

		private static final long serialVersionUID = 1L;

		private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss")
				.withZone(ZoneId.systemDefault());

		private final String[] columns = { "Test", "State", "Progress", "Completed", "Last update", "Message" };
		private List<FuzzerTestStatus> statuses = List.of();

		void refresh() {
			statuses = FuzzerStatusRegistry.getInstance().snapshot();
			fireTableDataChanged();
		}

		@Override
		public int getRowCount() {
			return statuses.size();
		}

		@Override
		public int getColumnCount() {
			return columns.length;
		}

		@Override
		public String getColumnName(int column) {
			return columns[column];
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			FuzzerTestStatus status = statuses.get(rowIndex);
			return switch (columnIndex) {
			case 0 -> status.getName();
			case 1 -> status.getState();
			case 2 -> status.getProgressPercentage() + " %";
			case 3 -> status.getCompleted() + " / " + status.getTotal();
			case 4 -> TIME_FORMATTER.format(Instant.ofEpochMilli(status.getUpdatedAt()));
			case 5 -> status.getMessage();
			default -> "";
			};
		}
	}

	private static class FlowTableModel extends AbstractTableModel {

		private static final long serialVersionUID = 1L;

		private final String[] columns = { "TLS", "Step", "Actor", "Category", "Status", "Bytes", "Response",
				"Description" };
		private List<TLSHandshakeStep> steps = TLSHandshakeFlows.all();
		private java.util.Map<String, TLSHandshakeStepStatus> statuses = java.util.Map.of();

		void refresh() {
			java.util.Map<String, TLSHandshakeStepStatus> next = new java.util.HashMap<>();
			for (TLSHandshakeStepStatus status : FuzzerStatusRegistry.getInstance().handshakeStepSnapshot()) {
				next.put(status.key(), status);
			}
			statuses = next;
			fireTableDataChanged();
		}

		@Override
		public int getRowCount() {
			return steps.size();
		}

		@Override
		public int getColumnCount() {
			return columns.length;
		}

		@Override
		public String getColumnName(int column) {
			return columns[column];
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			TLSHandshakeStep step = steps.get(rowIndex);
			TLSHandshakeStepStatus status = statuses.get(TLSHandshakeStepStatus.key(step.protocol(), step.sequence()));
			String state = status == null ? (step.implemented() ? "READY" : "PLANNED") : status.state();
			return switch (columnIndex) {
			case 0 -> step.protocol();
			case 1 -> step.sequence() + ". " + step.title();
			case 2 -> step.actor();
			case 3 -> step.category();
			case 4 -> status == null ? state : state + " " + status.jobName() + " #" + status.iteration();
			case 5 -> status == null ? "-" : status.requestBytes() + " / " + status.responseBytes();
			case 6 -> status == null ? "" : status.responseSummary();
			case 7 -> step.description();
			default -> "";
			};
		}

		TLSHandshakeStep stepAt(int rowIndex) {
			return steps.get(rowIndex);
		}

		String stateAt(int rowIndex) {
			TLSHandshakeStep step = stepAt(rowIndex);
			TLSHandshakeStepStatus status = statuses.get(TLSHandshakeStepStatus.key(step.protocol(), step.sequence()));
			return status == null ? (step.implemented() ? "READY" : "PLANNED") : status.state();
		}
	}

	private static class TerminalCellRenderer extends DefaultTableCellRenderer {

		private static final long serialVersionUID = 1L;

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
				int row, int column) {
			Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
			component.setFont(MONO);
			if (!isSelected) {
				component.setBackground(row % 2 == 0 ? BACKGROUND : new Color(1, 14, 7));
				component.setForeground(column == 1 ? ACCENT : TEXT_GREEN);
			}
			setBorder(new EmptyBorder(2, 8, 2, 8));
			return component;
		}
	}

	private static class FlowCellRenderer extends DefaultTableCellRenderer {

		private static final long serialVersionUID = 1L;

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
				int row, int column) {
			Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
			component.setFont(MONO);
			if (!isSelected) {
				FlowTableModel model = (FlowTableModel) table.getModel();
				TLSHandshakeStep step = model.stepAt(row);
				String state = model.stateAt(row);
				component.setForeground(foregroundFor(step, state, column));
				component.setBackground(backgroundFor(state, row));
			}
			setBorder(new EmptyBorder(2, 8, 2, 8));
			return component;
		}

		private Color foregroundFor(TLSHandshakeStep step, String state, int column) {
			if (column == 0) {
				return Color.decode(TLSHandshakeFlows.protocolColor(step.protocol()));
			}
			if ("TESTING".equals(state)) {
				return ACCENT;
			}
			if ("OBSERVED".equals(state)) {
				return CYAN;
			}
			if ("PLANNED".equals(state)) {
				return new Color(101, 217, 139);
			}
			return column == 4 ? Color.decode(step.color()) : TEXT_GREEN;
		}

		private Color backgroundFor(String state, int row) {
			if ("TESTING".equals(state)) {
				return new Color(54, 50, 8);
			}
			if ("OBSERVED".equals(state)) {
				return new Color(3, 30, 34);
			}
			return row % 2 == 0 ? BACKGROUND : new Color(1, 14, 7);
		}
	}
}
