from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLabel
)
from ccl_chromium_cache import convert_cache
import sys


class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cache Converter")
        self.resize(400, 200)
        layout = QVBoxLayout()

        self.label = QLabel("Select input and output folders.")
        self.input_label = QLabel("Input: Not selected")
        self.output_label = QLabel("Output: Not selected")
        self.btn_in = QPushButton("Select Input Folder")
        self.btn_out = QPushButton("Select Output Folder")
        self.btn_run = QPushButton("Run Conversion")

        layout.addWidget(self.label)
        layout.addWidget(self.input_label)
        layout.addWidget(self.btn_in)
        layout.addWidget(self.output_label)
        layout.addWidget(self.btn_out)
        layout.addWidget(self.btn_run)

        self.setLayout(layout)

        self.input_dir = ""
        self.output_dir = ""

        self.btn_in.clicked.connect(self.choose_input)
        self.btn_out.clicked.connect(self.choose_output)
        self.btn_run.clicked.connect(self.run_conversion)

    def choose_input(self):
        self.input_dir = QFileDialog.getExistingDirectory(
            self, "Select Input Folder (Cache Directory)"
        )
        if self.input_dir:
            self.input_label.setText(f"Input: {self.input_dir}")

    def choose_output(self):
        self.output_dir = QFileDialog.getExistingDirectory(
            self, "Select Output Folder"
        )
        if self.output_dir:
            self.output_label.setText(f"Output: {self.output_dir}")

    def run_conversion(self):
        if self.input_dir and self.output_dir:
            self.label.setText("Converting... Please wait.")
            self.btn_run.setEnabled(False)
            QApplication.processEvents()
            
            try:
                convert_cache(self.input_dir, self.output_dir + "/processed_files")
                self.label.setText("✓ Conversion complete!")
            except Exception as e:
                self.label.setText(f"Error: {str(e)}")
            finally:
                self.btn_run.setEnabled(True)
        else:
            self.label.setText("⚠ Please select both folders before running.")


def main():
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()