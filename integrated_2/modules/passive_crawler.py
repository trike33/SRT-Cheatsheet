from PyQt5.QtCore import QObject, pyqtSignal, QThread
from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
import asyncio
import nest_asyncio

# Apply nest_asyncio to allow asyncio event loop to run within another
nest_asyncio.apply()

class CrawlerAddon:
    def __init__(self, url_discovered_signal):
        self.url_discovered = url_discovered_signal

    def response(self, flow: http.HTTPFlow):
        # Emit the URL of every response received
        self.url_discovered.emit(flow.request.pretty_url)

class CrawlerWorker(QThread):
    url_discovered = pyqtSignal(str)

    def __init__(self, port=8080, parent=None):
        super().__init__(parent)
        self.port = port
        self.master = None
        self.loop = None

    def run(self):
        opts = Options(listen_host='127.0.0.1', listen_port=self.port)
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.master.addons.add(CrawlerAddon(self.url_discovered))
        
        self.loop = asyncio.get_event_loop()
        self.loop.run_until_complete(self.master.run())

    def stop(self):
        if self.master:
            self.master.shutdown()
