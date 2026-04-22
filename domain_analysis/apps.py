import os
from django.apps import AppConfig


class DomainAnalysisConfig(AppConfig):

    name = "domain_analysis"

    def ready(self):
        # Only build heavy data structures in the actual server process,
        # not in the reloader parent. Cuts startup from ~8min to ~4min.
        if os.environ.get('RUN_MAIN', 'false') == 'true':
            from .services.bloom_filter import build_bloom
            from .services.trie_index import build_trie

            build_bloom()
            build_trie()