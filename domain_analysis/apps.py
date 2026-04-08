from django.apps import AppConfig


class DomainAnalysisConfig(AppConfig):

    name = "domain_analysis"

    def ready(self):

        from .services.bloom_filter import build_bloom
        from .services.trie_index import build_trie

        build_bloom()
        build_trie()