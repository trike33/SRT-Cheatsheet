from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QPushButton, QHBoxLayout, QMessageBox
from urllib.parse import urlparse
from .passive_crawler import CrawlerWorker
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
import os

class SitemapWidget(QWidget):
    """
    A dedicated widget to display the sitemap of the target application,
    populated by a passive crawler.
    """
    def __init__(self, working_directory, parent=None):
        super().__init__(parent)
        self.working_directory = working_directory
        
        main_layout = QVBoxLayout(self)
        
        # --- Controls ---
        controls_layout = QHBoxLayout()
        self.crawler_button = QPushButton("Start Passive Crawler")
        self.crawler_button.setCheckable(True)
        self.crawler_button.clicked.connect(self.toggle_crawler)
        controls_layout.addWidget(self.crawler_button)
        controls_layout.addStretch()
        main_layout.addLayout(controls_layout)

        # --- Tree ---
        self.sitemap_tree = QTreeWidget()
        self.sitemap_tree.setHeaderLabels(["Sitemap"])
        main_layout.addWidget(self.sitemap_tree)
        
        self.crawler_worker = None
        self.browser = None
        self.roots = {}

    def toggle_crawler(self, checked):
        if checked:
            try:
                self.start_crawler()
                self.crawler_button.setText("Stop Passive Crawler")
            except Exception as e:
                QMessageBox.critical(self, "Crawler Error", f"Could not start the crawler: {e}")
                self.crawler_button.setChecked(False)
        else:
            self.stop_crawler()
            self.crawler_button.setText("Start Passive Crawler")
    
    def start_crawler(self):
        port = 8080
        self.crawler_worker = CrawlerWorker(port=port)
        self.crawler_worker.url_discovered.connect(self.add_url_to_sitemap)
        self.crawler_worker.start()
        
        # Launch browser with proxy settings
        options = webdriver.ChromeOptions()
        options.add_argument(f'--proxy-server=127.0.0.1:{port}')
        options.add_argument('--ignore-certificate-errors') # Needed for mitmproxy's cert
        self.browser = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
    
    def stop_crawler(self):
        if self.crawler_worker:
            self.crawler_worker.stop()
            self.crawler_worker.wait()
        if self.browser:
            self.browser.quit()
        self.roots = {} # Clear the sitemap hosts

    def add_url_to_sitemap(self, url):
        try:
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            if not host:
                return

            if host not in self.roots:
                self.roots[host] = QTreeWidgetItem(self.sitemap_tree, [host])
            
            parent_item = self.roots[host]
            path_parts = [part for part in parsed_url.path.split('/') if part]
            
            for part in path_parts:
                child_item = None
                for i in range(parent_item.childCount()):
                    if parent_item.child(i).text(0) == part:
                        child_item = parent_item.child(i)
                        break
                if not child_item:
                    child_item = QTreeWidgetItem(parent_item, [part])
                parent_item = child_item
            
        except Exception as e:
            # Handle potential parsing errors
            print(f"Error adding URL to sitemap: {e}")

    def closeEvent(self, event):
        """Ensure crawler and browser are closed when the widget is closed."""
        self.stop_crawler()
        super().closeEvent(event)

    def set_working_directory(self, path):
        """Updates the working directory."""
        self.working_directory = path