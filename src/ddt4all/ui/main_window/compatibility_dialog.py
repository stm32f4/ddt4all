"""End-of-scan dialog presenting the compatibility probe results (checkInGroup).

Reads CompatibilityReport objects, lets the user tick PASS group
representatives and returns the chosen CompatibilityResult list.
"""

import PyQt5.QtCore as core
import PyQt5.QtGui as gui
import PyQt5.QtWidgets as widgets

import ddt4all.options as options
from ddt4all.core.ecu.ecu_compatibility import (
    RESULT_FAIL,
    RESULT_PASS,
)

_ = options.translator('ddt4all')

COL_SELECT = 0
COL_STATUS = 1
COL_ECU = 2
COL_ID = 3
COL_PROTOCOL = 4
COL_SUPPLIER = 5
COL_DIAG = 6
COL_SOFT = 7
COL_VERSION = 8
COL_TESTS = 9

STATUS_SYMBOL = {RESULT_PASS: "✓", RESULT_FAIL: "✗"}
STATUS_COLOR = {RESULT_PASS: gui.QColor(0, 150, 0), RESULT_FAIL: gui.QColor(200, 0, 0)}
DEFAULT_SYMBOL = "—"
DEFAULT_COLOR = gui.QColor(128, 128, 128)

RESULT_ROLE = core.Qt.UserRole + 1


class CompatibilityDialog(widgets.QDialog):
    def __init__(self, reports, parent=None):
        super(CompatibilityDialog, self).__init__(parent)
        self.setWindowTitle(_("ECU compatibility check"))
        self.resize(900, 500)
        self._results = {}

        layout = widgets.QVBoxLayout(self)
        intro = widgets.QLabel(_("No definition matched these ECUs. Groups marked with a green tick answered "
                                 "the read-only probe correctly and can be added to the detected ECUs."))
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.tree = widgets.QTreeWidget()
        self.tree.setColumnCount(10)
        self.tree.setHeaderLabels([_("Select"), _("State"), _("ECU"), _("ID"), _("Protocol"),
                                   _("Supplier"), _("Diag"), _("Soft"), _("Version"),
                                   _("Pass / Fail / Inconclusive")])
        self.tree.setSelectionMode(widgets.QAbstractItemView.NoSelection)
        layout.addWidget(self.tree)

        for report in reports:
            self._add_report(report)
        self.tree.expandAll()
        for col in range(10):
            self.tree.resizeColumnToContents(col)

        buttons = widgets.QHBoxLayout()
        buttons.addStretch()
        self.add_button = widgets.QPushButton(_("Add selection"))
        self.add_button.clicked.connect(self.accept)
        self.close_button = widgets.QPushButton(_("Close"))
        self.close_button.clicked.connect(self.reject)
        buttons.addWidget(self.add_button)
        buttons.addWidget(self.close_button)
        layout.addLayout(buttons)

    def _add_report(self, report):
        identity = report.identity
        ecu_item = widgets.QTreeWidgetItem(self.tree)
        ecu_item.setFlags(core.Qt.ItemIsEnabled)
        functions = []
        for result in report.results:
            function = getattr(result.group.representative, "group", "")
            if function and function not in functions:
                functions.append(function)
        ecu_item.setText(COL_SELECT, ", ".join(functions) or _("ECU"))
        ecu_item.setText(COL_ECU, "%s @ %s" % (identity.project, identity.addr))
        ecu_item.setText(COL_ID, identity.addr)
        ecu_item.setText(COL_PROTOCOL, "%s / %s %d" % (identity.protocol, _("CAN line"), identity.canline))
        ecu_item.setText(COL_SUPPLIER, identity.supplier)
        ecu_item.setText(COL_DIAG, identity.diagversion)
        ecu_item.setText(COL_SOFT, identity.soft)
        ecu_item.setText(COL_VERSION, identity.version)
        bold = ecu_item.font(COL_ECU)
        bold.setBold(True)
        for col in range(10):
            ecu_item.setFont(col, bold)

        for result in report.results:
            self._add_result(ecu_item, result)

    def _add_result(self, parent, result):
        group = result.group
        rep = group.representative
        item = widgets.QTreeWidgetItem(parent)
        selectable = result.status == RESULT_PASS
        if selectable:
            item.setFlags(core.Qt.ItemIsEnabled | core.Qt.ItemIsUserCheckable)
            item.setCheckState(COL_SELECT, core.Qt.Unchecked)
        else:
            item.setFlags(core.Qt.ItemIsEnabled)
        item.setText(COL_STATUS, STATUS_SYMBOL.get(result.status, DEFAULT_SYMBOL))
        item.setForeground(COL_STATUS, gui.QBrush(STATUS_COLOR.get(result.status, DEFAULT_COLOR)))
        item.setToolTip(COL_STATUS, "%s %s" % (result.status, result.reason))
        item.setText(COL_ECU, rep.name)
        item.setText(COL_ID, str(rep.addr))
        item.setText(COL_PROTOCOL, rep.protocol)
        item.setText(COL_SUPPLIER, rep.supplier)
        item.setText(COL_DIAG, rep.diagversion)
        item.setText(COL_SOFT, rep.soft)
        item.setText(COL_VERSION, rep.version)
        item.setText(COL_TESTS, "%d / %d / %d" % (result.passed, result.failed, result.inconclusive))
        item.setData(COL_SELECT, RESULT_ROLE, id(result))
        self._results[id(result)] = result

        for member in group.members[1:]:
            child = widgets.QTreeWidgetItem(item)
            child.setFlags(core.Qt.ItemIsEnabled)
            child.setText(COL_ECU, member.name)
            child.setText(COL_ID, str(member.addr))
            child.setText(COL_PROTOCOL, member.protocol)
            child.setText(COL_SUPPLIER, member.supplier)
            child.setText(COL_DIAG, member.diagversion)
            child.setText(COL_SOFT, member.soft)
            child.setText(COL_VERSION, member.version)
            child.setForeground(COL_ECU, gui.QBrush(DEFAULT_COLOR))

    def selected_results(self):
        """CompatibilityResult objects whose representative row is checked."""
        chosen = []
        for i in range(self.tree.topLevelItemCount()):
            ecu_item = self.tree.topLevelItem(i)
            for j in range(ecu_item.childCount()):
                group_item = ecu_item.child(j)
                if (group_item.flags() & core.Qt.ItemIsUserCheckable
                        and group_item.checkState(COL_SELECT) == core.Qt.Checked):
                    result = self._results.get(group_item.data(COL_SELECT, RESULT_ROLE))
                    if result is not None:
                        chosen.append(result)
        return chosen
